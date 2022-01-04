import json
import sys
from .extension_util_base import *

try:
    from org.slf4j import LoggerFactory
    USE_LOGGING_FALLBACK = False
    logger = LoggerFactory.getLogger("com.recordedfuture.rf-extension-api")
except:
    print('falling back to native logging')
    USE_LOGGING_FALLBACK = True
    logger = None


def log(extension_name, message, level):
    if USE_LOGGING_FALLBACK: return print_log(extension_name, message, level)
    log_msg = "{0}: {1}".format(extension_name, message)
    if level == "debug":
        logger.debug(log_msg)
    elif level == "info":
        logger.info(log_msg)
    elif level == "warn":
        logger.warn(log_msg)
    elif level == "error":
        logger.error(log_msg)


def print_log(extension_name, message, level):
    message = "{0} {1} [{2}]: {3}".format(str(datetime.now()), level.upper(), extension_name, message)
    print(message)


def make_request(request):
    return request(json.loads(sys.argv[1]), json.loads(sys.argv[2]))


if __name__ == "__main__":
    import os
    print(open(os.path.abspath(os.path.sep.join([__file__, "..", "README.TXT"]))).read())
