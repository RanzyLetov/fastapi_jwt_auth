from uuid import uuid4
import random
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel, EmailStr, Field

class UserSchema(BaseModel):
    username: str
    first_name: str
    email: EmailStr

    is_verified: bool = False
    rule: str = "user"
    id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserInDBSchema(UserSchema):
    hashed_password: str

class UserRegisterSchema(BaseModel):
    username: str
    first_name: str
    email: EmailStr
    password: str
    password_confirm: str

class UserResponseSchema(BaseModel):
    access_token: str
    user: UserSchema

class UserRefreshInDBSchema(BaseModel):
    user_id: str
    expires_at: datetime

    jti: str = Field(default_factory=lambda: str(uuid4()))

class UserVerificationInDBSchema(BaseModel):
    user_id: str
    code: str
    expires_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=15))

class UserVerifySchema(BaseModel):
    code: str
