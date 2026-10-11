"""Console + file logging, configured once."""
import logging
import sys

from backend.config import settings


def configure_logging() -> logging.Logger:
    logger = logging.getLogger("secura")
    if logger.handlers:  # already configured — never double-add handlers
        return logger

    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
    )

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    logger.addHandler(console)

    settings.logs_dir.mkdir(parents=True, exist_ok=True)
    logfile = logging.FileHandler(
        settings.logs_dir / "secura.log", encoding="utf-8"
    )
    logfile.setFormatter(formatter)
    logger.addHandler(logfile)

    logger.propagate = False
    return logger
