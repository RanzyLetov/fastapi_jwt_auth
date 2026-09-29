from datetime import datetime, timedelta, timezone
from uuid import uuid4

import bcrypt
import jwt
from fastapi import HTTPException, status

from app.core.config import settings
from app.schemas.token import AnyTokenDataSchema


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        password.encode("utf-8"),
        hashed_password.encode("utf-8"),
    )


def create_access_token(user_id: str, is_verified: bool) -> str:
    time = datetime.now(timezone.utc)

    payload = AnyTokenDataSchema(
        sub=user_id,
        is_verified=is_verified,
        exp=time + timedelta(minutes=15),
        iat=time,
        type="access",
    ).model_dump()

    return jwt.encode(payload, key=settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    time = datetime.now(timezone.utc)

    payload = AnyTokenDataSchema(
        sub=user_id,
        exp=time + timedelta(days=30),
        iat=time,
        type="refresh",
        jti=str(uuid4()),
    ).model_dump()

    return jwt.encode(payload, key=settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_token(token: str) -> AnyTokenDataSchema:
    try:
        decoded_dict = jwt.decode(token, key=settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        decoded_dict["exp"] = datetime.fromtimestamp(timestamp=decoded_dict["exp"], tz=timezone.utc)
        decoded_dict["iat"] = datetime.fromtimestamp(timestamp=decoded_dict["iat"], tz=timezone.utc)
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED) from None

    return AnyTokenDataSchema(**decoded_dict)
