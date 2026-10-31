"""Configure application logging at startup, without touching the root logger.

By default, JSON records go to stderr (or stdout when stderr is unavailable).
No files or directories are created, so this works in a read-only container.
Windowed desktop executables may have neither stream; they use a NullHandler.

Set DIAGDISCOVER_LOG_DIR to an absolute, writable directory to additionally
enable demo.log with 5 MiB rotation and three backups. This is opt-in because
the application directory may be read-only or inside a frozen executable.
An unavailable log directory falls back to stream logging, without preventing
the application from starting. LOG_LEVEL accepts DEBUG, INFO, WARNING, ERROR,
or CRITICAL (also WARN/FATAL); invalid values use INFO. Settings are read once
per process, so restart after changing them.

Use logging.getLogger("diagdiscover.<module>") in application modules. Do not
log credentials or request bodies: JSON escaping prevents forged log records,
but is not a substitute for keeping secrets out of log messages.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import sys
import threading


LOGGER_NAME = "diagdiscover"
_HANDLER_MARKER = "_diagdiscover_owned"
_CONFIGURE_LOCK = threading.Lock()
_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "WARN": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
    "FATAL": logging.CRITICAL,
}


class JsonFormatter(logging.Formatter):
    """Serialize one record per line, including multiline exceptions safely."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "time": datetime.fromtimestamp(record.created, timezone.utc)
                .isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "level": record.levelname,
            "module": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)
        # Only the fields above are serialized; arbitrary LogRecord extras
        # (which may contain credentials or non-JSON objects) are excluded.
        return json.dumps(payload, ensure_ascii=True, allow_nan=False)


def configure_logging() -> logging.Logger:
    """Configure and return the application's logger, once per process.

    Existing root and third-party logger handlers and levels are preserved.
    Children of ``diagdiscover`` inherit this logger's handlers and level.
    """
    with _CONFIGURE_LOCK:
        logger = logging.getLogger(LOGGER_NAME)
        if any(getattr(handler, _HANDLER_MARKER, False)
               for handler in logger.handlers):
            return logger

        level_name = os.environ.get("LOG_LEVEL", "INFO").strip().upper()
        logger.setLevel(_LEVELS.get(level_name, logging.INFO))
        logger.propagate = False
        formatter = JsonFormatter()
        stream = sys.stderr if sys.stderr is not None else sys.stdout
        stream_handler = (logging.StreamHandler(stream) if stream is not None
                          else logging.NullHandler())
        stream_handler.setFormatter(formatter)
        setattr(stream_handler, _HANDLER_MARKER, True)
        logger.addHandler(stream_handler)

        log_directory = os.environ.get("DIAGDISCOVER_LOG_DIR", "").strip()
        if log_directory:
            try:
                directory = Path(log_directory).expanduser()
                if not directory.is_absolute():
                    raise ValueError("An absolute log directory is required")
                directory.mkdir(parents=True, exist_ok=True)
                file_handler = RotatingFileHandler(
                    directory / "demo.log", maxBytes=5 * 1024 * 1024,
                    backupCount=3, encoding="utf-8",
                )
            except (OSError, ValueError, RuntimeError):
                # Do not include the configured path or exception text: those
                # can reveal user details and are not needed for recovery.
                logger.warning("File logging unavailable; using stream logging when available")
            else:
                file_handler.setFormatter(formatter)
                setattr(file_handler, _HANDLER_MARKER, True)
                logger.addHandler(file_handler)

        if level_name not in _LEVELS:
            logger.warning("Invalid LOG_LEVEL; using INFO")
        return logger

