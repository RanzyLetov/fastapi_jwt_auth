from datetime import datetime

from pydantic import BaseModel


class AnyTokenData(BaseModel):
    sub: str
    exp: datetime
    iat: datetime
    type: str
    is_verified: bool = False
    jti: str


class TokenRefresh(BaseModel):
    access_token: str
