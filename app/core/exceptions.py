class AppException(Exception):
    pass


class InfrastructureException(AppException):
    pass


class EmailDeliveryError(InfrastructureException):
    pass
