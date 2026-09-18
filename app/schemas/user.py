from datetime import datetime
from pydantic import BaseModel, EmailStr

class UserSchema(BaseModel):
    id: str
    username: str
    first_name: str
    email: EmailStr
    rule: str
    created_at: datetime

class UserInDBSchema(UserSchema):
    hashed_password: str

class UserRegisterSchema(BaseModel):
    username: str
    first_name: str
    email: EmailStr
    password: str
    password_confirm: str

class UserLoginSchema(BaseModel):
    email: EmailStr
    password: str

class UserResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    user: UserSchema


class UserRefreshInDBSchema(BaseModel):
    user_id: str
    jti: str
    expires_at: datetime