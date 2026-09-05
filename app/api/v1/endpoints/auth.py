from uuid import uuid4
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from app.schemas.user import UserInDBSchema, UserRegisterSchema, UserSchema, UserLoginSchema, UserResponseSchema
from app.core.security import hash_password, verify_password, create_access_token, create_refresh_token

router = APIRouter(prefix="/auth", tags=["Authentication"])

USERS_DB: list[UserInDBSchema] = []

@router.post("/register")
def register(payload: UserRegisterSchema):
    for user in USERS_DB: 
        if user.email == payload.email: 
            raise HTTPException(status_code=404, detail="Такая почта привязана к другому аккаунту.")
        if user.username == payload.username:
            raise HTTPException(status_code=404, detail="Такой username уже существует.")

    if not payload.password == payload.password_confirm:
        raise HTTPException(status_code=404, detail="Пароли не совпадают.")
    
    new_user = UserInDBSchema(
        id=str(uuid4()),
        username=payload.username,
        first_name=payload.first_name,
        email=payload.email,
        rule="user",
        created_at=datetime.now(timezone.utc),
        hashed_password=hash_password(payload.password),
    )

    USERS_DB.append(new_user)    

    return UserSchema.model_validate(new_user)

@router.post("/login")
def login(payload: UserLoginSchema):
    found = None
    for user in USERS_DB: 
        if user.email == payload.email: 
            found = user
            break

    if found is None:
        raise HTTPException(status_code=404, detail="Почта или пароль неверны.")

    if not verify_password(password=payload.password, hashed_password=found.hashed_password):
        raise HTTPException(status_code=404, detail="Почта или пароль неверны.")

    return UserResponseSchema(
        access_token=create_access_token(found.id),
        refresh_token=create_refresh_token(found.id),
        user=UserSchema.model_validate(found)
    )
    
