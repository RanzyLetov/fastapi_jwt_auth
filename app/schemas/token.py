from datetime import datetime

from pydantic import BaseModel


class AnyTokenDataSchema(BaseModel):
    sub: str
    exp: datetime
    iat: datetime
    type: str
    is_verified: bool = False
    jti: str


class TokenRefreshSchema(BaseModel):
    access_token: str
