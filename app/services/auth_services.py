import random
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from fastapi.concurrency import run_in_threadpool
from fastapi_mail import FastMail, MessageSchema, MessageType, NameEmail
from sqlalchemy import delete, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.session import Session

from app.core.config import email_config, settings
from app.core.logger import logger
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.models.user import Refresh, User, Verification


class AuthService:
    def __init__(self, db: Session):
        self.db = db

    def create_user(
        self, username: str, first_name: str, email: str, password: str, password_confirm: str
    ):
        if password != password_confirm:
            raise HTTPException(status_code=400, detail="Passwords do not match.")

        existing_user = (
            self.db.query(User).filter(or_(User.email == email, User.username == username)).first()
        )

        if existing_user:
            logger.warning("Attempted to register with existing email/username: %s", email)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email or username already exists.",
            )

        db_user = User(
            username=username,
            first_name=first_name,
            email=email,
            hashed_password=hash_password(password),
        )

        self.db.add(db_user)

        try:
            self.db.commit()
            self.db.refresh(db_user)
        except IntegrityError:
            logger.warning("User already exists")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email or username already exists.",
            ) from None

        logger.info("User registered successfully: %s", db_user.id)

    def authenticate_user(
        self,
        username: str,
        password: str,
    ):

        found_user = self.db.query(User).filter(User.email == username).first()

        if found_user is None:
            verify_password(password=password, hashed_password=settings.DEFAULT_HASHED_PASSWORD)
            logger.warning("Invalid email or password: %s", username)
            raise HTTPException(status_code=401, detail="Invalid email or password") from None

        if not verify_password(password=password, hashed_password=found_user.hashed_password):
            logger.warning("Invalid email or password: %s", username)
            raise HTTPException(status_code=401, detail="Invalid email or password") from None

        access_token = create_access_token(found_user.id, found_user.is_verified)
        refresh_token = create_refresh_token(found_user.id)
        refresh_token_data = decode_token(refresh_token)

        db_refresh_token = Refresh(
            user_id=found_user.id,
            jti=refresh_token_data.jti,
            expires_at=refresh_token_data.exp,
        )

        self.db.add(db_refresh_token)

        logger.info("User logged in successfully: %s", found_user.id)

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": found_user,
        }

    def revoke_refresh_token(
        self,
        refresh_token: str,
    ):
        try:
            refresh_token_data = decode_token(refresh_token)

            self.db.query(Refresh).filter(Refresh.jti == refresh_token_data.jti).delete(
                synchronize_session=False
            )

            logger.info("User logged out successfully: %s", refresh_token_data.sub)
        except Exception:
            logger.warning("Attempted logout with invalid token")

    def revoke_all_user_tokens(
        self,
        user_id: str,
    ):
        self.db.query(Refresh).filter(Refresh.user_id == user_id).delete(synchronize_session=False)

        logger.info("User logged out successfully: %s", user_id)

    def rotate_refresh_token(
        self,
        refresh_token: str,
    ):
        refresh_token_data = decode_token(refresh_token)

        stmt = delete(Refresh).where(Refresh.jti == refresh_token_data.jti).returning(Refresh)
        result = self.db.execute(stmt)
        found_token = result.scalar_one_or_none()

        if found_token is None:
            self.db.query(Refresh).filter(Refresh.user_id == refresh_token_data.sub).delete(
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

        self.db.add(new_refresh_token_db)

        logger.info("Token refreshed successfully: %s", refresh_token_data.sub)
        return {
            "new_access_token": new_access_token,
            "new_refresh_token": new_refresh_token,
        }

    async def initiate_email_verification(
        self,
        user_id: str,
    ):
        user_email = await run_in_threadpool(
            self.db.query(User.email).filter(User.id == user_id).scalar()
        )
        if user_email is None:
            logger.warning("User not found: %s", user_id)
            raise HTTPException(status_code=404, detail="User not found") from None

        random_code: str = str(random.randint(100000, 999999))
        expire_time = datetime.now(timezone.utc) + timedelta(minutes=15)

        found_verification = (
            self.db.query(Verification).filter(Verification.user_id == user_id).first()
        )

        if found_verification:
            found_verification.code = random_code
            found_verification.expires_at = expire_time
        else:
            db_verification = Verification(
                user_id=user_id, code=random_code, expires_at=expire_time
            )
            self.db.add(db_verification)

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
            logger.error("Failed to send email for user_id: %s. Reason: %s", user_id, str(exc))
            raise HTTPException(
                status_code=500, detail="Failed to send email, please try again later"
            ) from None

        logger.info("Verification code sent for user_id: %s", user_id)

    def confirm_email(
        self,
        code: str,
        user_id: str,
    ):
        found_entry = (
            self.db
            .query(Verification)
            .filter(
                Verification.user_id == user_id,
                Verification.code == code,
                Verification.expires_at > datetime.now(timezone.utc),
            )
            .first()
        )

        if found_entry is None:
            logger.warning("Invalid code or code has expired: %s", user_id)
            raise HTTPException(
                status_code=401, detail="Invalid code or code has expired"
            ) from None

        found_user = self.db.query(User).filter(User.id == user_id).first()

        if found_user is None:
            logger.warning("User not found: %s", user_id)
            raise HTTPException(status_code=404, detail="User not found") from None

        found_user.is_verified = True

        self.db.delete(found_entry)

        logger.info("Email verified successfully: %s", user_id)
