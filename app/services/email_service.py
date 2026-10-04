from fastapi_mail import FastMail, MessageSchema, MessageType, NameEmail
from pydantic import EmailStr

from app.core.config import email_config
from app.core.exceptions import EmailDeliveryError
from app.core.logger import logger


class EmailService:
    def __init__(self):
        self.fm = FastMail(email_config)

    async def send_verification_code(self, code: str, email: str):
        message = MessageSchema(
            subject="Verification Code",
            body=code,
            recipients=[NameEmail(name="", email=email)],
            subtype=MessageType.plain,
        )

        try:
            await self.fm.send_message(message)
        except Exception as exc:
            logger.error("Failed to send verification email to %s", email, exc_info=True)
            raise EmailDeliveryError("Failed to send email") from exc

    async def send_reset_code(self, code: str, email: EmailStr):
        message = MessageSchema(
            subject="Reset Code",
            body=code,
            recipients=[NameEmail(name="", email=email)],
            subtype=MessageType.plain,
        )

        try:
            await self.fm.send_message(message)
        except Exception as exc:
            logger.error("Failed to send reset email to %s", email, exc_info=True)
            raise EmailDeliveryError("Failed to send email") from exc
