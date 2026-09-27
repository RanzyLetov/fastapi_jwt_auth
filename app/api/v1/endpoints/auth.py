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
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Эта почта или имя пользователя уже существует.",
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
    except IntegrityError as e:
        raise HTTPException(status_code=409, detail="Такой пользователь уже существует") from e

    return {"message": "Регистрация прошла успешно."}


@router.post("/login")
def login(
    response: Response,
    payload: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[Session, Depends(get_db)],
):

    found_user = db.query(User).filter(User.email == payload.username).first()

    if found_user is None:
        verify_password(password=payload.password, hashed_password=settings.DEFAULT_HASHED_PASSWORD)
        raise HTTPException(status_code=401, detail="Почта или пароль не верны")

    if not verify_password(password=payload.password, hashed_password=found_user.hashed_password):
        raise HTTPException(status_code=401, detail="Почта или пароль не верны")

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
        secure=False,  # Нужно будет поменять на проде с https
    )

    return UserResponseSchema(access_token=access_token, user=UserSchema.model_validate(found_user))


@router.post("/logout")
def logout(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    refresh_token: str | None = Cookie(None),
):
    if refresh_token is None:
        response.delete_cookie(key="refresh_token")
        return {"message": "Успешный выход"}

    refresh_token_data = decode_token(refresh_token)

    db.query(Refresh).filter(Refresh.jti == refresh_token_data.jti).delete(
        synchronize_session=False
    )

    response.delete_cookie(key="refresh_token")

    return {"message": "Успешный выход"}


@router.post("/logout-all")
def logout_all(
    response: Response,
    token_data: Annotated[AnyTokenDataSchema, Depends(get_token_from_header)],
    db: Annotated[Session, Depends(get_db)],
):
    db.query(Refresh).filter(Refresh.user_id == token_data.sub).delete(synchronize_session=False)

    response.delete_cookie(key="refresh_token")

    return {"message": "Успешный выход"}


@router.post("/refresh")
def refresh(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    refresh_token: str | None = Cookie(None),
) -> TokenRefreshSchema:
    if refresh_token is None:
        raise HTTPException(status_code=401, detail="Refresh-токен не найден в куках")

    refresh_token_data = decode_token(refresh_token)

    stmt = delete(Refresh).where(Refresh.jti == refresh_token_data.jti).returning(Refresh)
    result = db.execute(stmt)
    found_token = result.scalar_one_or_none()

    if found_token is None:
        db.query(Refresh).filter(Refresh.user_id == refresh_token_data.sub).delete(
            synchronize_session=False
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
        secure=False,  # Нужно будет поменять на проде с https
    )

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
        raise HTTPException(status_code=404, detail="Пользователь не найден")

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
        subject="Код подтверждения",
        body=random_code,
        recipients=[NameEmail(name="", email=user_email)],
        subtype=MessageType.plain,
    )

    fm = FastMail(email_config)
    try:
        await fm.send_message(message)
    except Exception as e:
        raise HTTPException(
            status_code=500, detail="Письмо не удалось отправить, попробуйте позже"
        ) from e

    return {"message": "Код успешно отправлен на вашу почту."}


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
        raise HTTPException(status_code=401, detail="Неверный код или срок действия истек.")

    found_user = db.query(User).filter(User.id == token_data.sub).first()

    if found_user is None:
        raise HTTPException(status_code=404, detail="Такой пользователь не найден")

    found_user.is_verified = True

    db.delete(found_entry)

    return {"message": "Почта успешно подтверждена!"}
