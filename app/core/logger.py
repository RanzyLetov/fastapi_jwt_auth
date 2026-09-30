import logging
from pathlib import Path


def get_logger():

    logger = logging.getLogger("auth")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        log_file_path = Path.cwd() / "py_log.log"

        file_logger = logging.FileHandler(log_file_path, mode="a", encoding="utf-8")
        console_logger = logging.StreamHandler()

        formatter = logging.Formatter("%(asctime)s | %(name)s | %(levelname)s | %(message)s")

        file_logger.setFormatter(formatter)
        console_logger.setFormatter(formatter)

        logger.addHandler(file_logger)
        logger.addHandler(console_logger)
        logger.propagate = True
    return logger


logger = get_logger()
