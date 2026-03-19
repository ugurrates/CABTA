"""
Tests for structured logging - text and JSON formatters.
"""

import json
import logging
import os
import pytest

from src.utils.logger import setup_logger, JSONFormatter, _make_formatter


class TestSetupLogger:
    """Test setup_logger() configuration."""

    def test_returns_logger(self):
        logger = setup_logger('test-basic')
        assert isinstance(logger, logging.Logger)
        assert logger.name == 'test-basic'

    def test_sets_level(self):
        logger = setup_logger('test-level', level='DEBUG')
        assert logger.level == logging.DEBUG

    def test_invalid_level_falls_back(self):
        logger = setup_logger('test-bad-level', level='NONEXISTENT')
        assert logger.level == logging.INFO

    def test_no_propagation(self):
        logger = setup_logger('test-propagation')
        assert logger.propagate is False

    def test_clears_existing_handlers(self):
        logger = setup_logger('test-clear')
        initial_count = len(logger.handlers)
        # Call again - should not add duplicate handlers
        setup_logger('test-clear')
        assert len(logger.handlers) == initial_count

    def test_file_handler_created(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        logger = setup_logger('test-file', log_file=log_file)
        logger.info("file log test")
        # Should have 2 handlers: console + file
        assert len(logger.handlers) == 2
        assert (tmp_path / "test.log").exists()

    def test_file_handler_uses_json(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        logger = setup_logger('test-file-json', log_file=log_file)
        logger.info("structured test")
        # Flush
        for h in logger.handlers:
            h.flush()
        content = (tmp_path / "test.log").read_text(encoding='utf-8').strip()
        # File handler always uses JSON
        parsed = json.loads(content)
        assert parsed['message'] == 'structured test'
        assert parsed['level'] == 'INFO'


class TestJSONFormatter:
    """Test JSONFormatter output."""

    def test_produces_valid_json(self):
        formatter = JSONFormatter(datefmt='%Y-%m-%dT%H:%M:%S')
        record = logging.LogRecord(
            name='test', level=logging.WARNING,
            pathname='test.py', lineno=42,
            msg='test message', args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed['level'] == 'WARNING'
        assert parsed['message'] == 'test message'
        assert parsed['line'] == 42

    def test_includes_extra_fields(self):
        formatter = JSONFormatter(datefmt='%Y-%m-%dT%H:%M:%S')
        record = logging.LogRecord(
            name='test', level=logging.INFO,
            pathname='test.py', lineno=1,
            msg='ioc checked', args=(), exc_info=None,
        )
        record.ioc = '8.8.8.8'
        record.score = 42
        record.source = 'VirusTotal'
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed['ioc'] == '8.8.8.8'
        assert parsed['score'] == 42
        assert parsed['source'] == 'VirusTotal'

    def test_exception_included(self):
        formatter = JSONFormatter(datefmt='%Y-%m-%dT%H:%M:%S')
        try:
            raise ValueError("boom")
        except ValueError:
            import sys
            exc_info = sys.exc_info()
        record = logging.LogRecord(
            name='test', level=logging.ERROR,
            pathname='test.py', lineno=1,
            msg='failed', args=(), exc_info=exc_info,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert 'exception' in parsed
        assert 'ValueError' in parsed['exception']

    def test_no_extra_fields_when_absent(self):
        formatter = JSONFormatter(datefmt='%Y-%m-%dT%H:%M:%S')
        record = logging.LogRecord(
            name='test', level=logging.INFO,
            pathname='test.py', lineno=1,
            msg='plain', args=(), exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert 'ioc' not in parsed
        assert 'score' not in parsed


class TestFormatSelection:
    """Test LOG_FORMAT env var and log_format parameter."""

    def test_text_format_default(self):
        logger = setup_logger('test-text-default')
        handler = logger.handlers[0]
        assert not isinstance(handler.formatter, JSONFormatter)

    def test_json_format_via_param(self):
        logger = setup_logger('test-json-param', log_format='json')
        handler = logger.handlers[0]
        assert isinstance(handler.formatter, JSONFormatter)

    def test_json_format_via_env(self, monkeypatch):
        monkeypatch.setenv('LOG_FORMAT', 'json')
        logger = setup_logger('test-json-env')
        handler = logger.handlers[0]
        assert isinstance(handler.formatter, JSONFormatter)

    def test_param_overrides_env(self, monkeypatch):
        monkeypatch.setenv('LOG_FORMAT', 'json')
        logger = setup_logger('test-override', log_format='text')
        handler = logger.handlers[0]
        assert not isinstance(handler.formatter, JSONFormatter)

    def test_make_formatter_text(self):
        f = _make_formatter('text')
        assert not isinstance(f, JSONFormatter)

    def test_make_formatter_json(self):
        f = _make_formatter('json')
        assert isinstance(f, JSONFormatter)
