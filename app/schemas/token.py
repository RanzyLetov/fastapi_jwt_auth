from datetime import datetime
from uuid import uuid4

from pydantic import BaseModel, Field


class TokenDataSchema(BaseModel):
    sub: str
    exp: datetime
    iat: datetime
    type: str

    jti: str = Field(default_factory=lambda: str(uuid4()))


class TokenRefreshSchema(BaseModel):
    access_token: str
