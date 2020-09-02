import logging
from logging.handlers import RotatingFileHandler
import os


def build_logger(name: str, log_path: str, log_level: str = "INFO", file_size: int = 20000000, backup_count: int = 12):
    try:
        os.mkdir(log_path)
    except FileExistsError:
        pass

    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    if not logger.handlers:
        console_handler = logging.StreamHandler()
        # console_handler.setLevel(log_level)

        formatter = logging.Formatter('%(asctime)s | %(lineno)d | %(levelname)s | %(message)s')
        if "DISABLE_FILE_LOGS" not in os.environ:
            handler = RotatingFileHandler("{}/agent-{}.log".format(log_path, name), maxBytes=file_size,
                                          backupCount=backup_count)
            # handler.setLevel(log_level)
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger
