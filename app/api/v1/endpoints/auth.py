from typing import Annotated

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Cookie,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.security import OAuth2PasswordRequestForm

from app.api.v1.dependencies import get_auth_service, get_token_from_header
from app.core.logger import logger
from app.core.rate_limiter import limiter
from app.schemas.token import AnyTokenData, TokenRefresh
from app.schemas.user import (
    ForgotPassword,
    MessageResponse,
    ResetPassword,
    User,
    UserRegister,
    UserResponse,
    UserVerify,
)
from app.services.auth_services import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register")
def register(payload: UserRegister, service: Annotated[AuthService, Depends(get_auth_service)]):
    try:
        service.create_user(
            username=payload.username,
            first_name=payload.first_name,
            email=payload.email,
            password=payload.password,
            password_confirm=payload.password_confirm,
        )

        return MessageResponse(message="Registration successful.")

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

        return UserResponse(
            access_token=result["access_token"], user=User.model_validate(result["user"])
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

    return MessageResponse(message="Successfully logged out.")


@router.post("/logout-all")
def logout_all(
    response: Response,
    token_data: Annotated[AnyTokenData, Depends(get_token_from_header)],
    service: Annotated[AuthService, Depends(get_auth_service)],
):
    service.revoke_all_user_tokens(user_id=token_data.sub)

    response.delete_cookie(key="refresh_token")

    return MessageResponse(message="Successfully logged out.")


@router.post("/refresh")
def refresh(
    response: Response,
    service: Annotated[AuthService, Depends(get_auth_service)],
    refresh_token: str | None = Cookie(None),
) -> TokenRefresh:
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

        return TokenRefresh(access_token=result["new_access_token"])
    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err)) from err


@router.post("/resend-code")
@limiter.limit("5/hour")
async def send_verification_code(
    request: Request,
    token_data: Annotated[AnyTokenData, Depends(get_token_from_header)],
    service: Annotated[AuthService, Depends(get_auth_service)],
    background_tasks: BackgroundTasks,
):
    try:
        background_tasks.add_task(service.initiate_email_verification, token_data.sub)
        return MessageResponse(message="Verification code sent to your email.")

    except RuntimeError:
        raise HTTPException(
            status_code=500, detail="Failed to send email, please try again later"
        ) from None


@router.post("/verify-email")
@limiter.limit("5/minute")
def verify_email(
    request: Request,
    payload: UserVerify,
    token_data: Annotated[AnyTokenData, Depends(get_token_from_header)],
    service: Annotated[AuthService, Depends(get_auth_service)],
):
    service.confirm_email(code=payload.code, user_id=token_data.sub)

    return MessageResponse(message="Email successfully verified.")


@router.post("/forgot-password")
@limiter.limit("3/hour")
async def forgot_password(
    request: Request,
    payload: ForgotPassword,
    service: Annotated[AuthService, Depends(get_auth_service)],
    background_tasks: BackgroundTasks,
):

    service.request_password_reset(payload.email, background_tasks)

    return MessageResponse(
        message="If the email is registered, a password reset code has been sent."
    )


@router.post("/reset-password")
@limiter.limit("5/minute")
def reset_password(
    request: Request,
    payload: ResetPassword,
    service: Annotated[AuthService, Depends(get_auth_service)],
):
    service.complete_password_reset(
        code=payload.code,
        email=payload.email,
        new_password=payload.new_password,
    )

    return MessageResponse(message="Password has been successfully reset.")
