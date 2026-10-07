from datetime import datetime, timedelta, timezone
from typing import Self
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, EmailStr, Field, model_validator


class User(BaseModel):
    username: str
    first_name: str
    email: EmailStr

    is_verified: bool = False
    rule: str = "user"
    id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(from_attributes=True)


class UserInDB(User):
    hashed_password: str


class UserRegister(BaseModel):
    username: str
    first_name: str
    email: EmailStr
    password: str
    password_confirm: str

    @model_validator(mode="after")
    def check_passwords_match(self) -> Self:
        if self.password != self.password_confirm:
            raise ValueError("Passwords do not match")
        return self


class UserResponse(BaseModel):
    access_token: str
    user: User


class UserRefreshInDBSchema(BaseModel):
    user_id: str
    expires_at: datetime

    jti: str = Field(default_factory=lambda: str(uuid4()))


class UserVerificationInDB(BaseModel):
    user_id: str
    code: str
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=15)
    )


class UserVerify(BaseModel):
    code: str

class ForgotPassword(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
    code: str
    email: EmailStr
    new_password: str
    new_password_confirm: str

    @model_validator(mode="after")
    def check_new_passwords_match(self) -> Self:
        if self.new_password != self.new_password_confirm:
            raise ValueError("New passwords do not match")
        return self