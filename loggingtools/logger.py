import logging
from logging.handlers import RotatingFileHandler
import os


def build_logger(name: str, log_path: str, log_level: str = "INFO"):
    try:
        os.mkdir(log_path)
    except FileExistsError:
        pass

    logger = logging.getLogger(name)
    logger.setLevel(log_level)

    handler = RotatingFileHandler("{}/{}.log".format(log_path, name), maxBytes=20000000, backupCount=12)
    handler.setLevel(log_level)

    formatter = logging.Formatter('%(asctime)s | %(lineno)d | %(levelname)s | %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger