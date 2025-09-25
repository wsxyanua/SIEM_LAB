import logging
import os
import time
from logging.handlers import RotatingFileHandler
from typing import Optional

from .config import DATA_DIR_DEFAULT


class SIEMLogger:
    """Centralized logging for SIEM system"""
    
    def __init__(self, log_dir: Optional[str] = None):
        self.log_dir = log_dir or os.path.join(DATA_DIR_DEFAULT, "logs")
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Main SIEM logger
        self.siem_logger = logging.getLogger("siem")
        self.siem_logger.setLevel(logging.INFO)
        
        # Security events logger
        self.security_logger = logging.getLogger("siem.security")
        self.security_logger.setLevel(logging.WARNING)
        
        # Performance logger
        self.perf_logger = logging.getLogger("siem.performance")
        self.perf_logger.setLevel(logging.INFO)
        
        self._setup_handlers()
    
    def _setup_handlers(self):
        """Setup file handlers with rotation"""
        
        # Main log file (rotates at 10MB, keeps 5 files)
        main_handler = RotatingFileHandler(
            os.path.join(self.log_dir, "siem.log"),
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        main_handler.setFormatter(
            logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        )
        self.siem_logger.addHandler(main_handler)
        
        # Security events log (rotates at 5MB, keeps 10 files)
        security_handler = RotatingFileHandler(
            os.path.join(self.log_dir, "security.log"),
            maxBytes=5*1024*1024,  # 5MB
            backupCount=10
        )
        security_handler.setFormatter(
            logging.Formatter(
                '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
            )
        )
        self.security_logger.addHandler(security_handler)
        
        # Performance log
        perf_handler = RotatingFileHandler(
            os.path.join(self.log_dir, "performance.log"),
            maxBytes=5*1024*1024,  # 5MB
            backupCount=3
        )
        perf_handler.setFormatter(
            logging.Formatter(
                '%(asctime)s - PERF - %(levelname)s - %(message)s'
            )
        )
        self.perf_logger.addHandler(perf_handler)
        
        # Console handler for important messages
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.WARNING)
        console_handler.setFormatter(
            logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
        )
        self.siem_logger.addHandler(console_handler)
    
    def info(self, message: str, **kwargs):
        """Log info message"""
        self.siem_logger.info(message, extra=kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self.siem_logger.warning(message, extra=kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message"""
        self.siem_logger.error(message, extra=kwargs)
    
    def security_event(self, event_type: str, ip: str, details: str, **kwargs):
        """Log security event"""
        message = f"{event_type} from {ip}: {details}"
        self.security_logger.warning(message, extra=kwargs)
        # Also log to main logger
        self.siem_logger.warning(f"SECURITY: {message}", extra=kwargs)
    
    def block_event(self, ip: str, reason: str, duration: int, **kwargs):
        """Log IP blocking event"""
        message = f"BLOCKED IP {ip} for {duration}s - Reason: {reason}"
        self.security_logger.error(message, extra=kwargs)
        self.siem_logger.error(message, extra=kwargs)
    
    def unblock_event(self, ip: str, **kwargs):
        """Log IP unblocking event"""
        message = f"UNBLOCKED IP {ip}"
        self.security_logger.info(message, extra=kwargs)
        self.siem_logger.info(message, extra=kwargs)
    
    def performance(self, operation: str, duration_ms: float, **kwargs):
        """Log performance metrics"""
        message = f"{operation} took {duration_ms:.2f}ms"
        self.perf_logger.info(message, extra=kwargs)


# Global logger instance
logger = SIEMLogger()
