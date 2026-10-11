from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from app.core.exceptions import UserNotFoundError
from app.core.rate_limiter import _rate_limit_exceeded_handler


def register_exception_handlers(app: FastAPI) -> None:
    
    @app.exception_handler(UserNotFoundError)
    async def user_not_found_handler(request: Request, exc: UserNotFoundError):
        return JSONResponse(status_code=404, content={"detail": exc.message})
        
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
