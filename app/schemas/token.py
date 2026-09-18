from datetime import datetime
from pydantic import BaseModel

class TokenDataSchema(BaseModel):
    sub: str
    exp: datetime
    iat: datetime
    type: str
    jti: str 

class TokenRefreshSchema(BaseModel):
    refresh_token: str
    access_token: str
