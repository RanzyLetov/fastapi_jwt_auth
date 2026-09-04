import jwt
import bcrypt
from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.schemas.token import TokenData

def heah_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        password.encode("utf-8"),
        hashed_password.encode("utf-8"),
    )

def create_access_token(user_id: str) -> str:
    time = datetime.now(timezone.utc)

    payload = TokenData(
        sub=user_id,
        exp=time + timedelta(minutes=15),
        iat=time,
    ).model_dump()

    return jwt.encode(payload, settings.ACCESS_KEY, algorithm=settings.ALGORITHM)

def create_refresh_token(user_id: str) -> str:
    time = datetime.now(timezone.utc)

    payload = TokenData(
        sub=user_id,
        exp=time + timedelta(days=30),
        iat=time,
    ).model_dump()

    return jwt.encode(payload, settings.REFRESH_KEY, algorithm=settings.ALGORITHM)
