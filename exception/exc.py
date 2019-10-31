class InitException(Exception):
    def __init__(self, message):
        super(Exception, self).__init__(message)


class ValidationException(Exception):
    def __init__(self, message):
        super(Exception, self).__init__(message)


class ComposeException(ValidationException):
    def __init__(self, message):
        super(Exception, self).__init__(message)


class StartException(Exception):
    def __init__(self, message):
        super(Exception, self).__init__(message)


class ContainerException(Exception):
    def __init__(self, message):
        super(Exception, self).__init__(message)


class PongFailedException(Exception):
    def __init__(self, message):
        super(Exception, self).__init__(message)
