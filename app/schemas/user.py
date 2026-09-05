from pydantic import BaseModel, EmailStr
from datetime import datetime

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