import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.core.config import settings
from app.schemas.token import TokenDataSchema

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

def get_token_from_header(token: str = Depends(oauth2_scheme)) -> TokenDataSchema:
    try:
        token_dist = jwt.decode(token, key=settings.SECRET_KEY, algorithms=settings.ALGORITHM)
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    return TokenDataSchema(**token_dist)
    