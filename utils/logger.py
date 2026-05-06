"""
DNS Threat Monitor Logging Utilities
===================================

Centralized logging configuration and utilities for consistent
logging across all system components.
"""

import logging
import logging.handlers
from pathlib import Path
from config.config import Config


class Logger:
    """
    Centralized logging utility for DNS Threat Monitor.
    Provides consistent logging configuration and formatting.
    """

    # Log levels
    LEVELS = {
        'DEBUG': logging.DEBUG,
        'INFO': logging.INFO,
        'WARNING': logging.WARNING,
        'ERROR': logging.ERROR,
        'CRITICAL': logging.CRITICAL
    }

    _logger = None
    _configured = False

    @classmethod
    def get_logger(cls, name: str = None) -> logging.Logger:
        """
        Get a configured logger instance.

        Args:
            name: Logger name (usually __name__)

        Returns:
            Configured logger instance
        """
        if not cls._configured:
            cls._configure_logging()

        if name:
            return logging.getLogger(name)
        else:
            return logging.getLogger('dns_monitor')

    @classmethod
    def _configure_logging(cls):
        """Configure the logging system."""
        if cls._configured:
            return

        # Create logger
        logger = logging.getLogger('dns_monitor')
        logger.setLevel(cls.LEVELS.get(Config.LOG_LEVEL, logging.INFO))

        # Remove existing handlers to avoid duplicates
        logger.handlers.clear()

        # Create formatters
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        console_formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )

        # File handler with rotation
        try:
            file_handler = logging.handlers.RotatingFileHandler(
                Config.get_log_path(),
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            print(f"Warning: Could not create log file handler: {e}")

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(cls.LEVELS.get(Config.LOG_LEVEL, logging.INFO))
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

        cls._logger = logger
        cls._configured = True

        # Log configuration
        logger.info("Logging system initialized")
        logger.info(f"Log level: {Config.LOG_LEVEL}")
        logger.info(f"Log file: {Config.get_log_path()}")

    @classmethod
    def log_system_info(cls):
        """Log system information for debugging."""
        logger = cls.get_logger()
        logger.info("=== System Information ===")
        logger.info(f"Project Root: {Config.PROJECT_ROOT}")
        logger.info(f"Database: {Config.DATABASE_FILE}")
        logger.info(f"Processing Threads: {Config.PROCESSING_THREADS}")
        logger.info(f"Queue Size: {Config.QUEUE_SIZE}")
        logger.info("===========================")


# Convenience functions for easy logging
def get_logger(name: str = None) -> logging.Logger:
    """Get a configured logger instance."""
    return Logger.get_logger(name)


def log_performance(func_name: str, start_time: float, end_time: float):
    """Log performance information for a function."""
    duration = end_time - start_time
    logger = get_logger()
    logger.debug(f"Performance: {func_name} took {duration:.4f} seconds")


# Context manager for timing operations
class Timer:
    """Context manager for timing code blocks."""

    def __init__(self, name: str, logger=None):
        self.name = name
        self.logger = logger or get_logger()
        self.start_time = None

    def __enter__(self):
        self.start_time = logging.time.time()
        self.logger.debug(f"Starting: {self.name}")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        end_time = logging.time.time()
        duration = end_time - self.start_time
        self.logger.debug(f"Completed: {self.name} in {duration:.4f} seconds")


# Initialize logging on import
Logger._configure_logging()
