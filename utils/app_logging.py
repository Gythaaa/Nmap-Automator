"""Small logging helpers for recoverable application failures."""

import logging
from pathlib import Path


def log_exception_to_file(log_path: Path, message: str) -> None:
    """Write the current exception and full traceback to a UTF-8 log file."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setLevel(logging.ERROR)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s"
    ))

    logger = logging.getLogger("nmap_automator")
    previous_level = logger.level
    previous_propagate = logger.propagate
    logger.setLevel(logging.ERROR)
    logger.propagate = False
    logger.addHandler(handler)
    try:
        logger.exception(message)
        handler.flush()
    finally:
        logger.removeHandler(handler)
        handler.close()
        logger.setLevel(previous_level)
        logger.propagate = previous_propagate
