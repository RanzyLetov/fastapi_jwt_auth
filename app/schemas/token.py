from datetime import datetime

from pydantic import BaseModel


class TokenData(BaseModel):
    sub: str
    exp: datetime
    iat: datetime
    type: str
    is_verified: bool | None = None
    role: str | None = None
    jti: str


class AccessTokenData(BaseModel):
    sub: str
    exp: datetime
    iat: datetime
    type: str
    is_verified: bool
    role: str
    jti: str


class RefreshTokenData(BaseModel):
    sub: str
    exp: datetime
    iat: datetime
    type: str
    jti: str


class TokenRefresh(BaseModel):
    access_token: str
