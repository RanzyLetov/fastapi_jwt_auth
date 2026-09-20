from app.schemas.user import UserInDBSchema, UserRefreshInDBSchema, UserVerificationInDBSchema

USERS_DB: list[UserInDBSchema] = []
REFRESH_TOKEN_DB: list[UserRefreshInDBSchema] = []
VERIFICATION_CODES_DB: list[UserVerificationInDBSchema] = []