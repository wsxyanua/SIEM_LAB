import ipaddress
import os
from dataclasses import dataclass, field
from typing import List, Optional

try:
	import yaml  # type: ignore
except Exception:
	yaml = None


@dataclass
class DetectorConfig:
	failures_threshold: int = 5
	window_seconds: int = 180
	block_seconds: int = 86400
	auth_logs: List[str] = field(default_factory=lambda: [
		"/var/log/auth.log",
		"/var/log/secure",
	])
	whitelist: List[str] = field(default_factory=lambda: [
		"127.0.0.1/32",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	])
	ipset_name: str = "ssh_bruteforce_blacklist"
	iptables_chain: str = "INPUT"


CONFIG_PATH_CANDIDATES = [
	"/etc/mini_siem/config.yaml",
	os.path.expanduser("~/.config/mini_siem/config.yaml"),
]


def _load_yaml(path: str) -> dict:
	if yaml is None:
		return {}
	try:
		with open(path, "r", encoding="utf-8") as f:
			return yaml.safe_load(f) or {}
	except FileNotFoundError:
		return {}


def load_config() -> DetectorConfig:
	cfg = DetectorConfig()
	for path in CONFIG_PATH_CANDIDATES:
		over = _load_yaml(path)
		if not over:
			continue
		if "failures_threshold" in over:
			cfg.failures_threshold = int(over["failures_threshold"])
		if "window_seconds" in over:
			cfg.window_seconds = int(over["window_seconds"])
		if "block_seconds" in over:
			cfg.block_seconds = int(over["block_seconds"])
		if "auth_logs" in over and isinstance(over["auth_logs"], list):
			cfg.auth_logs = [str(p) for p in over["auth_logs"]]
		if "whitelist" in over and isinstance(over["whitelist"], list):
			cfg.whitelist = [str(c) for c in over["whitelist"]]
		if "ipset_name" in over:
			cfg.ipset_name = str(over["ipset_name"])
		if "iptables_chain" in over:
			cfg.iptables_chain = str(over["iptables_chain"])
	return cfg


def is_ip_whitelisted(ip: str, whitelist: List[str]) -> bool:
	try:
		ip_obj = ipaddress.ip_address(ip)
	except ValueError:
		return False
	for net in whitelist:
		try:
			network = ipaddress.ip_network(net, strict=False)
		except ValueError:
			continue
		if ip_obj in network:
			return True
	return False


DATA_DIR_DEFAULT = os.path.expanduser("~/.local/share/mini_siem")
DB_PATH_DEFAULT = os.path.join(DATA_DIR_DEFAULT, "mini_siem.db")


def ensure_data_dir(path: Optional[str] = None) -> str:
	target = path or DATA_DIR_DEFAULT
	os.makedirs(target, exist_ok=True)
	return target
