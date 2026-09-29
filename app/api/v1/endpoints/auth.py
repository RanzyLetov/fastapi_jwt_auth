import random
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from fastapi.concurrency import run_in_threadpool
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_mail import FastMail, MessageSchema, MessageType, NameEmail
from sqlalchemy import delete, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.v1.dependencies import get_token_from_header
from app.core.config import email_config, settings
from app.core.database import get_db
from app.core.logger import logger
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.models.user import Refresh, User, Verification
from app.schemas.token import AnyTokenDataSchema, TokenRefreshSchema
from app.schemas.user import (
    UserRegisterSchema,
    UserResponseSchema,
    UserSchema,
    UserVerifySchema,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register")
def register(
    payload: UserRegisterSchema,
    db: Annotated[Session, Depends(get_db)],
):

    existing_email = (
        db
        .query(User)
        .filter(or_(User.email == payload.email, User.username == payload.username))
        .first()
    )

    if existing_email:
        logger.warning("Attempted to register with existing email/username: %s", payload.email)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or username already exists.",
        )

    db_user = User(
        username=payload.username,
        first_name=payload.first_name,
        email=payload.email,
        hashed_password=hash_password(payload.password),
    )

    db.add(db_user)

    try:
        db.commit()
    except IntegrityError:
        logger.warning("User already exists")
        raise HTTPException(status_code=409, detail="User already exists") from None

    logger.info("User registered successfully: %s", db_user.id)
    return {"message": "Registration successful."}


@router.post("/login")
def login(
    response: Response,
    payload: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[Session, Depends(get_db)],
):

    found_user = db.query(User).filter(User.email == payload.username).first()

    if found_user is None:
        verify_password(password=payload.password, hashed_password=settings.DEFAULT_HASHED_PASSWORD)
        logger.warning("Invalid email or password: %s", payload.username)
        raise HTTPException(status_code=401, detail="Invalid email or password") from None

    if not verify_password(password=payload.password, hashed_password=found_user.hashed_password):
        logger.warning("Invalid email or password: %s", payload.username)
        raise HTTPException(status_code=401, detail="Invalid email or password") from None

    access_token = create_access_token(found_user.id, found_user.is_verified)
    refresh_token = create_refresh_token(found_user.id)
    refresh_token_data = decode_token(refresh_token)

    db_refresh_token = Refresh(
        user_id=found_user.id,
        jti=refresh_token_data.jti,
        expires_at=refresh_token_data.exp,
    )

    db.add(db_refresh_token)

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        samesite="lax",
        secure=False,  # TODO: Set secure=True in production with HTTPS
    )

    logger.info("User logged in successfully: %s", found_user.id)
    return UserResponseSchema(access_token=access_token, user=UserSchema.model_validate(found_user))


@router.post("/logout")
def logout(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    refresh_token: str | None = Cookie(None),
):
    if refresh_token is None:
        response.delete_cookie(key="refresh_token")
        return {"message": "Successfully logged out"}

    refresh_token_data = decode_token(refresh_token)

    db.query(Refresh).filter(Refresh.jti == refresh_token_data.jti).delete(
        synchronize_session=False
    )

    response.delete_cookie(key="refresh_token")

    logger.info("User logged out successfully: %s", refresh_token_data.sub)
    return {"message": "Successfully logged out"}


@router.post("/logout-all")
def logout_all(
    response: Response,
    token_data: Annotated[AnyTokenDataSchema, Depends(get_token_from_header)],
    db: Annotated[Session, Depends(get_db)],
):
    db.query(Refresh).filter(Refresh.user_id == token_data.sub).delete(synchronize_session=False)

    response.delete_cookie(key="refresh_token")

    logger.info("User logged out successfully: %s", token_data.sub)
    return {"message": "Successfully logged out"}


@router.post("/refresh")
def refresh(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    refresh_token: str | None = Cookie(None),
) -> TokenRefreshSchema:
    if refresh_token is None:
        logger.warning("Refresh token not found in cookies")
        raise HTTPException(status_code=401, detail="Refresh token not found in cookies") from None

    refresh_token_data = decode_token(refresh_token)

    stmt = delete(Refresh).where(Refresh.jti == refresh_token_data.jti).returning(Refresh)
    result = db.execute(stmt)
    found_token = result.scalar_one_or_none()

    if found_token is None:
        db.query(Refresh).filter(Refresh.user_id == refresh_token_data.sub).delete(
            synchronize_session=False
        )
        logger.warning(
            "Invalid or reused refresh token. User ID: %s, JTI: %s",
            refresh_token_data.sub,
            refresh_token_data.jti,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    new_access_token = create_access_token(found_token.user_id, refresh_token_data.is_verified)
    new_refresh_token = create_refresh_token(found_token.user_id)
    new_refresh_token_data = decode_token(new_refresh_token)

    new_refresh_token_db = Refresh(
        user_id=found_token.user_id,
        expires_at=new_refresh_token_data.exp,
        jti=new_refresh_token_data.jti,
    )

    db.add(new_refresh_token_db)

    response.set_cookie(
        key="refresh_token",
        value=new_refresh_token,
        httponly=True,
        samesite="lax",
        secure=False,  # TODO: Set secure=True in production with HTTPS
    )

    logger.info("Token refreshed successfully: %s", refresh_token_data.sub)
    return TokenRefreshSchema(access_token=new_access_token)


@router.post("/resend-code")
async def send_verification_code(
    token_data: Annotated[AnyTokenDataSchema, Depends(get_token_from_header)],
    db: Annotated[Session, Depends(get_db)],
):
    user_email = await run_in_threadpool(
        db.query(User.email).filter(User.id == token_data.sub).scalar()
    )
    if user_email is None:
        logger.warning("User not found: %s", token_data.sub)
        raise HTTPException(status_code=404, detail="User not found") from None

    random_code: str = str(random.randint(100000, 999999))
    expire_time = datetime.now(timezone.utc) + timedelta(minutes=15)

    found_verification = (
        db.query(Verification).filter(Verification.user_id == token_data.sub).first()
    )

    if found_verification:
        found_verification.code = random_code
        found_verification.expires_at = expire_time
    else:
        db_verification = Verification(
            user_id=token_data.sub, code=random_code, expires_at=expire_time
        )
        db.add(db_verification)

    message = MessageSchema(
        subject="Verification Code",
        body=random_code,
        recipients=[NameEmail(name="", email=user_email)],
        subtype=MessageType.plain,
    )

    fm = FastMail(email_config)
    try:
        await fm.send_message(message)
    except Exception as exc:
        logger.error("Failed to send email for user_id: %s. Reason: %s", token_data.sub, str(exc))
        raise HTTPException(
            status_code=500, detail="Failed to send email, please try again later"
        ) from None

    logger.info("Verification code sent for user_id: %s", token_data.sub)
    return {"message": "Verification code sent to your email."}


@router.post("/verify-email")
def verify_email(
    payload: UserVerifySchema,
    token_data: Annotated[AnyTokenDataSchema, Depends(get_token_from_header)],
    db: Annotated[Session, Depends(get_db)],
):
    found_entry = (
        db
        .query(Verification)
        .filter(
            Verification.user_id == token_data.sub,
            Verification.code == payload.code,
            Verification.expires_at > datetime.now(timezone.utc),
        )
        .first()
    )

    if found_entry is None:
        logger.warning("Invalid code or code has expired: %s", token_data.sub)
        raise HTTPException(status_code=401, detail="Invalid code or code has expired") from None

    found_user = db.query(User).filter(User.id == token_data.sub).first()

    if found_user is None:
        logger.warning("User not found: %s", token_data.sub)
        raise HTTPException(status_code=404, detail="User not found") from None

    found_user.is_verified = True

    db.delete(found_entry)

    logger.info("Email verified successfully: %s", token_data.sub)
    return {"message": "Email successfully verified!"}
