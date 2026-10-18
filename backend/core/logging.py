"""Console and rotating file logging, configured once per process."""
from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler

from backend.config import Settings

_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"


def configure_logging(settings: Settings, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger("secura")
    if getattr(logger, "_secura_configured", False):
        return logger

    logger.setLevel(level)
    formatter = logging.Formatter(_FORMAT)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    logger.addHandler(console)

    try:
        settings.logs_dir.mkdir(parents=True, exist_ok=True)
        logfile = RotatingFileHandler(
            settings.logs_dir / "secura.log",
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
        logfile.setFormatter(formatter)
        logger.addHandler(logfile)
    except OSError:
        logger.warning("File logging disabled: %s is not writable", settings.logs_dir)

    logger.propagate = False
    logger._secura_configured = True
    return logger
