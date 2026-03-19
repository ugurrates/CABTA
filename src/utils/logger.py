"""
Author: Ugur Ates
Centralized logging configuration for Blue Team Assistant.

Supports two output formats controlled by the ``LOG_FORMAT`` environment
variable:

* ``text`` (default) - human-readable single-line format
* ``json`` - structured JSON, one object per line (for SIEM ingestion)
"""

import json as _json
import logging
import os
import sys
import time
from typing import Optional
from pathlib import Path


class JSONFormatter(logging.Formatter):
    """Emit log records as single-line JSON objects.

    Useful for shipping logs to Elasticsearch, Splunk, or any SIEM that
    accepts structured JSON.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            'timestamp': self.formatTime(record, self.datefmt),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        if record.exc_info and record.exc_info[0] is not None:
            log_entry['exception'] = self.formatException(record.exc_info)
        # Merge any *extra* fields attached via ``logger.info("msg", extra={…})``
        for key in ('ioc', 'source', 'score', 'duration_ms', 'analysis_id',
                     'file_name', 'event_type'):
            value = getattr(record, key, None)
            if value is not None:
                log_entry[key] = value
        return _json.dumps(log_entry, ensure_ascii=False)


def _make_formatter(fmt: str = 'text') -> logging.Formatter:
    """Return the appropriate formatter for the requested format."""
    if fmt == 'json':
        return JSONFormatter(datefmt='%Y-%m-%dT%H:%M:%S')
    return logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )


def setup_logger(
    name: str = 'blue-team-assistant',
    level: str = 'INFO',
    log_file: Optional[str] = None,
    log_format: Optional[str] = None,
) -> logging.Logger:
    """
    Setup centralized logger.

    Args:
        name: Logger name
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        log_format: ``'text'`` or ``'json'``.  Falls back to the
                    ``LOG_FORMAT`` env var, then ``'text'``.

    Returns:
        Configured logger instance

    Example:
        >>> logger = setup_logger('blue-team-assistant', 'DEBUG')
        >>> logger.info("Analysis started")
    """
    logger = logging.getLogger(name)

    # Clear existing handlers
    logger.handlers.clear()

    # Set level
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    # Resolve format
    fmt = (log_format or os.environ.get('LOG_FORMAT', 'text')).lower()
    formatter = _make_formatter(fmt)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(numeric_level)
            # File logs always use JSON for machine parsing
            file_handler.setFormatter(_make_formatter('json'))
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"[LOGGER] Failed to setup file logging: {e}")

    # Prevent propagation to root logger
    logger.propagate = False

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get logger instance.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(name)
