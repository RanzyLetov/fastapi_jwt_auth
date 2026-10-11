class AppException(Exception):
    pass


class InfrastructureException(AppException):
    pass


class EmailDeliveryError(InfrastructureException):
    pass

class UserNotFoundError(AppException):
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.message = f"User with ID {user_id} was not found"
        super().__init__(self.message)