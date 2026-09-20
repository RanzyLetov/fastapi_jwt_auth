import random
from fastapi import APIRouter, Depends, HTTPException, status
from app.api.v1.dependencies import get_token_from_header
from app.core.security import create_access_token, create_refresh_token, decode_token, hash_password, verify_password
from app.schemas.token import TokenDataSchema, TokenRefreshSchema
from app.schemas.user import UserInDBSchema, UserLoginSchema, UserRefreshInDBSchema, UserRegisterSchema, UserResponseSchema, UserSchema, UserVerificationRequestSchema
from app.database import USERS_DB, REFRESH_TOKEN_DB, VERIFICATION_CODES_DB

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register")
def register(payload: UserRegisterSchema):
    for user in USERS_DB: 
        if user.email == payload.email: 
            raise HTTPException(status_code=409, detail="Эта почта уже привязана к другому аккаунту.")
        if user.username == payload.username:
            raise HTTPException(status_code=409, detail="Этот username уже занят.")

    if payload.password != payload.password_confirm:
        raise HTTPException(status_code=400, detail="Пароли не совпадают.")
    
    new_user = UserInDBSchema(
        username=payload.username,
        first_name=payload.first_name,
        email=payload.email,
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
        raise HTTPException(status_code=404, detail="Пользователь с такой почтой не найден.")

    if not verify_password(password=payload.password, hashed_password=found.hashed_password):
        raise HTTPException(status_code=401, detail="Неверный пароль.")
    
    access_token = create_access_token(found.id)
    refresh_token = create_refresh_token(found.id)
    refresh_token_data = decode_token(refresh_token)

    REFRESH_TOKEN_DB.append(UserRefreshInDBSchema(
        user_id=refresh_token_data.sub,
        jti=refresh_token_data.jti,
        expires_at=refresh_token_data.exp,
    ))

    return UserResponseSchema(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserSchema.model_validate(found)
    )

@router.post("/refresh")
def refresh(old_token_data: TokenDataSchema = Depends(get_token_from_header)) -> TokenRefreshSchema:
    found_id = None

    for token_entry in REFRESH_TOKEN_DB:
        if token_entry.jti == old_token_data.jti:
            found_id = token_entry.user_id
            REFRESH_TOKEN_DB.remove(token_entry)
            break

    if found_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    access_token = create_access_token(found_id)
    refresh_token = create_refresh_token(found_id)
    refresh_token_data = decode_token(refresh_token)

    REFRESH_TOKEN_DB.append(UserRefreshInDBSchema(
        user_id=refresh_token_data.sub,
        jti=refresh_token_data.jti,
        expires_at=refresh_token_data.exp,
    ))

    for user in USERS_DB:
        if user.id == found_id:
            return TokenRefreshSchema(
                access_token=access_token,
                refresh_token=refresh_token,
            )
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

@router.post("/verify-email")
def verify_email(payload: UserVerifySchema, token_data: TokenDataSchema = Depends(get_token_from_header)):
    found_entry = None

    for entry in VERIFICATION_CODES_DB:
        if entry.user_id == token_data.sub and entry.code == payload.code:
            found_entry = entry
            break

    if found_entry is None:
        raise HTTPException(status_code=401, detail="Неверный код подтверждения")


    if datetime.now(timezone.utc) > found_entry.expires_at:
        VERIFICATION_CODES_DB.remove(found_entry)
        raise HTTPException(status_code=401, detail="Срок действия кода истек")

    user_activated = False
    for db_user in USERS_DB:
        if db_user.id == token_data.sub:
            db_user.is_verified = True
            user_activated = True
            break

    if not user_activated:
        raise HTTPException(status_code=404, detail="Пользователь не найден")

    VERIFICATION_CODES_DB.remove(found_entry)

    return {"message": "Почта успешно подтверждена!"}

@router.post("/resend-code")
def send_verification_code(token_data: TokenDataSchema = Depends(get_token_from_header)):
    for entry in VERIFICATION_CODES_DB:
        if entry.user_id == token_data.sub:
            VERIFICATION_CODES_DB.remove(entry)

    random_code: str = str(random.randint(100000, 999999))

    VERIFICATION_CODES_DB.append(
        UserVerificationInDBSchema(
            user_id=token_data.sub,
            code=random_code,
        )
    )

    print(random_code)
