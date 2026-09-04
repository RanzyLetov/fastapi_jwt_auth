from pydantic import BaseModel
from datetime import datetime

class TokenData(BaseModel):
    sub: str
    exp: datetime
    iat: datetime
