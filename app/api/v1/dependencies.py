from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.logger import logger
from app.schemas.token import AnyTokenDataSchema
from app.services.auth_services import AuthService

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")


def get_token_from_header(token: str = Depends(oauth2_scheme)) -> AnyTokenDataSchema:
    try:
        token_dict = jwt.decode(token, key=settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except jwt.PyJWTError as err:
        logger.error("JWT decoding failed: %s", err)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials"
        ) from err

    return AnyTokenDataSchema(**token_dict)


def get_auth_service(db: Annotated[Session, Depends(get_db)]) -> AuthService:
    return AuthService(db)
