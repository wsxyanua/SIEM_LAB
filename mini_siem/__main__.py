import os

from .config import load_config
from .db import init_db
from .blocker import ensure_firewall
from .detector import parse_and_detect
from .logger import logger


def main() -> None:
	cfg = load_config()
	os.makedirs(os.path.dirname(os.path.expanduser("~/.local/share/mini_siem")), exist_ok=True)
	
	logger.info("Starting Mini SIEM system")
	logger.info(f"Configuration loaded: {cfg.failures_threshold} failures in {cfg.window_seconds}s")
	
	init_db()
	ensure_firewall(cfg)
	
	logger.info("Starting SSH brute force detection")
	parse_and_detect(cfg)


if __name__ == "__main__":
	main()
