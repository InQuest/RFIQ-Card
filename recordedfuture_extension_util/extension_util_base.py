from datetime import datetime


class ExtensionException(Exception):
    """Base class for all Extention exceptions"""
    pass


class ExtensionApiException(ExtensionException):
    def __init__(self, msg, link=None):
        self.msg = msg
        self.link = link
        self.message = self.msg


class AuthenticationFailedException(ExtensionException):
    def __init__(self):
        self.msg = "Authentication failed"
        self.message = self.msg


class MissingCredentialsException(ExtensionException):
    def __init__(self):
        self.msg = "No authentication credentials for extension"
        self.message = self.msg


class UnsupportedTypeException(ExtensionException):
    def __init__(self, arg):
        self.msg = "Type {} not supported for extension".format(arg)
        self.message = self.msg


class NoResultException(ExtensionException):
    def __init__(self, arg, link=None):
        self.msg = "No results found for {}".format(arg)
        self.link = link
        self.message = self.msg


def create_datetime(datetime_str):
    return datetime.fromtimestamp(datetime_str).isoformat()
