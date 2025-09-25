import os
import re
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Iterable, Optional, Tuple

from .config import DetectorConfig, is_ip_whitelisted
from .db import insert_event
from .blocker import block_ip
from .logger import logger
from .geoip import geoip_lookup
from .notifications import notification_manager

# Patterns for OpenSSH auth messages
# Example lines:
#   Failed password for invalid user test from 1.2.3.4 port 54321 ssh2
#   Failed password for root from 1.2.3.4 port 2222 ssh2
FAILED_PATTERN = re.compile(r"Failed password for (?:(invalid user )?(?P<user>\S+)) from (?P<ip>[0-9a-fA-F:\.]+) ")
INVALID_PATTERN = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:\.]+)")


class SlidingWindowCounter:
	def __init__(self, window_seconds: int) -> None:
		self.window_seconds = window_seconds
		self.ip_to_timestamps: Dict[str, Deque[int]] = defaultdict(deque)
		self.ip_to_usernames: Dict[str, set] = defaultdict(set)

	def add(self, ip: str, username: Optional[str] = None, ts: Optional[int] = None) -> int:
		timestamp = ts or int(time.time())
		q = self.ip_to_timestamps[ip]
		q.append(timestamp)
		self._evict_old(q, timestamp)
		
		if username:
			self.ip_to_usernames[ip].add(username)
		
		return len(q)

	def _evict_old(self, q: Deque[int], now_ts: int) -> None:
		limit = now_ts - self.window_seconds
		while q and q[0] < limit:
			q.popleft()

	def count(self, ip: str, now_ts: Optional[int] = None) -> int:
		now = now_ts or int(time.time())
		q = self.ip_to_timestamps.get(ip)
		if not q:
			return 0
		self._evict_old(q, now)
		return len(q)
	
	def get_usernames(self, ip: str) -> set:
		"""Get usernames attempted by this IP"""
		return self.ip_to_usernames.get(ip, set())


def _iter_new_lines(path: str):
	# Tail -F like reader with reopen on rotation
	inode = None
	f = None
	while True:
		try:
			st = os.stat(path)
			if inode != st.st_ino:
				if f:
					f.close()
				f = open(path, "r", encoding="utf-8", errors="ignore")
				f.seek(0, os.SEEK_END)
				inode = st.st_ino
			next_line = f.readline() if f else ""
			if next_line:
				yield next_line.rstrip("\n")
			else:
				time.sleep(0.5)
		except FileNotFoundError:
			# File may not exist yet; wait
			time.sleep(1.0)
		except Exception:
			time.sleep(1.0)


def parse_and_detect(cfg: DetectorConfig) -> None:
	counter = SlidingWindowCounter(cfg.window_seconds)
	for log_path in cfg.auth_logs:
		if not os.path.exists(log_path):
			continue
		for line in _iter_new_lines(log_path):
			_now = int(time.time())
			m = FAILED_PATTERN.search(line) or INVALID_PATTERN.search(line)
			if not m:
				continue
			ip = m.group("ip")
			user = m.groupdict().get("user")
			if is_ip_whitelisted(ip, cfg.whitelist):
				continue
			insert_event(_now, ip, user, "failed_login", line)
			logger.security_event("SSH_FAILED_LOGIN", ip, f"User: {user or 'unknown'}")
			
			current = counter.add(ip, user, _now)
			if current >= cfg.failures_threshold:
				# Get geolocation info
				geo_info = geoip_lookup.lookup(ip)
				usernames = list(counter.get_usernames(ip))
				
				logger.block_event(ip, f"Brute force detected ({current} attempts)", cfg.block_seconds)
				block_ip(cfg, ip, cfg.block_seconds, f"Brute force detected ({current} attempts)")
				
				# Send notifications
				notification_manager.notify_brute_force_detected(ip, current, usernames, geo_info)
				
				# reset window to avoid repeated blocks spam
				counter.ip_to_timestamps[ip].clear()
				counter.ip_to_usernames[ip].clear()
