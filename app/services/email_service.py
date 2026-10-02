from fastapi_mail import FastMail, MessageSchema, MessageType, NameEmail

from app.core.config import email_config
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
            logger.error("Failed to send verification email to %s. Reason: %s", email, str(exc))
            raise RuntimeError("Failed to send email") from exc
