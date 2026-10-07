from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.logger import logger
from app.schemas.token import AnyTokenData
from app.services.auth_services import AuthService
from app.services.email_service import EmailService

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")


def get_token_from_header(token: str = Depends(oauth2_scheme)) -> AnyTokenData:
    try:
        token_dict = jwt.decode(token, key=settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except jwt.PyJWTError as err:
        logger.error("JWT decoding failed: %s", err)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials"
        ) from err

    return AnyTokenData(**token_dict)


def get_email_service() -> EmailService:
    return EmailService()


def get_auth_service(
    db: Annotated[Session, Depends(get_db)],
    email_service: Annotated[EmailService, Depends(get_email_service)],
) -> AuthService:
    return AuthService(db, email_service)
