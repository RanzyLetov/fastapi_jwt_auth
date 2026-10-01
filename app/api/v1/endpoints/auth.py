from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm

from app.api.v1.dependencies import get_auth_service, get_token_from_header
from app.core.logger import logger
from app.core.rate_limiter import limiter
from app.schemas.token import AnyTokenDataSchema, TokenRefreshSchema
from app.schemas.user import (
    UserRegisterSchema,
    UserResponseSchema,
    UserSchema,
    UserVerifySchema,
)
from app.services.auth_services import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register")
def register(
    payload: UserRegisterSchema, service: Annotated[AuthService, Depends(get_auth_service)]
):
    try:
        service.create_user(
            username=payload.username,
            first_name=payload.first_name,
            email=payload.email,
            password=payload.password,
            password_confirm=payload.password_confirm,
        )
        return {"message": "Registration successful."}
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err)) from err


@router.post("/login")
@limiter.limit("5/minute")
def login(
    request: Request,
    response: Response,
    payload: Annotated[OAuth2PasswordRequestForm, Depends()],
    service: Annotated[AuthService, Depends(get_auth_service)],
):
    try:
        result = service.authenticate_user(
            username=payload.username,
            password=payload.password,
        )

        response.set_cookie(
            key="refresh_token",
            value=result["refresh_token"],
            httponly=True,
            samesite="lax",
            secure=False,  # TODO: Set secure=True in production with HTTPS
        )

        return UserResponseSchema(
            access_token=result["access_token"], user=UserSchema.model_validate(result["user"])
        )
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err)) from err


@router.post("/logout")
def logout(
    response: Response,
    service: Annotated[AuthService, Depends(get_auth_service)],
    refresh_token: str | None = Cookie(None),
):
    if refresh_token:
        service.revoke_refresh_token(refresh_token=refresh_token)

    response.delete_cookie(key="refresh_token")
    return {"message": "Successfully logged out"}


@router.post("/logout-all")
def logout_all(
    response: Response,
    token_data: Annotated[AnyTokenDataSchema, Depends(get_token_from_header)],
    service: Annotated[AuthService, Depends(get_auth_service)],
):
    service.revoke_all_user_tokens(user_id=token_data.sub)

    response.delete_cookie(key="refresh_token")
    return {"message": "Successfully logged out"}


@router.post("/refresh")
def refresh(
    response: Response,
    service: Annotated[AuthService, Depends(get_auth_service)],
    refresh_token: str | None = Cookie(None),
) -> TokenRefreshSchema:
    if refresh_token is None:
        logger.warning("Refresh token not found in cookies")
        raise HTTPException(status_code=401, detail="Refresh token not found in cookies") from None
    try:
        result = service.rotate_refresh_token(refresh_token=refresh_token)

        response.set_cookie(
            key="refresh_token",
            value=result["new_refresh_token"],
            httponly=True,
            samesite="lax",
            secure=False,  # TODO: Set secure=True in production with HTTPS
        )

        return TokenRefreshSchema(access_token=result["new_access_token"])
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err)) from err


@router.post("/resend-code")
@limiter.limit("5/hour")
async def send_verification_code(
    request: Request,
    token_data: Annotated[AnyTokenDataSchema, Depends(get_token_from_header)],
    service: Annotated[AuthService, Depends(get_auth_service)],
):
    await service.initiate_email_verification(user_id=token_data.sub)

    return {"message": "Verification code sent to your email."}


@router.post("/verify-email")
@limiter.limit("5/minute")
def verify_email(
    request: Request,
    payload: UserVerifySchema,
    token_data: Annotated[AnyTokenDataSchema, Depends(get_token_from_header)],
    service: Annotated[AuthService, Depends(get_auth_service)],
):
    service.confirm_email(code=payload.code, user_id=token_data.sub)

    return {"message": "Email successfully verified!"}
