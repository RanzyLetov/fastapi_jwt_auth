from pydantic import BaseModel, EmailStr

class UserSchema(BaseModel):
    id: str
    username: str
    email: EmailStr

class UserInDBSchema(UserSchema):
    hashed_password: str

