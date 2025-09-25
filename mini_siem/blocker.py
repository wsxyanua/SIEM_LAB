import subprocess
import time
from typing import List, Optional

from .config import DetectorConfig
from .db import insert_action
from .logger import logger
from .geoip import geoip_lookup
from .notifications import notification_manager


def _run(cmd: List[str]) -> subprocess.CompletedProcess:
	return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)


def ensure_firewall(cfg: DetectorConfig) -> None:
	# Ensure ipset exists
	res = _run(["ipset", "list", cfg.ipset_name])
	if res.returncode != 0:
		create = _run(["ipset", "create", cfg.ipset_name, "hash:ip", "timeout", "0"])  # timeout=0 means permanent until explicitly set per entry
		if create.returncode != 0:
			insert_action(None, "ensure_firewall", None, None, "error", create.stderr.strip())
			logger.error(f"Failed to create ipset {cfg.ipset_name}: {create.stderr}")
			return
		else:
			logger.info(f"Created ipset {cfg.ipset_name}")
	# Ensure iptables rule exists once
	check = _run(["iptables", "-C", cfg.iptables_chain, "-m", "set", "--match-set", cfg.ipset_name, "src", "-j", "DROP"]) 
	if check.returncode != 0:
		append = _run(["iptables", "-I", cfg.iptables_chain, "-m", "set", "--match-set", cfg.ipset_name, "src", "-j", "DROP"]) 
		if append.returncode != 0:
			insert_action(None, "ensure_firewall", None, None, "error", append.stderr.strip())
			logger.error(f"Failed to add iptables rule: {append.stderr}")
			return
		else:
			logger.info(f"Added iptables rule for ipset {cfg.ipset_name}")
	insert_action(None, "ensure_firewall", None, None, "ok", "ipset and iptables verified")
	logger.info("Firewall setup completed successfully")


def block_ip(cfg: DetectorConfig, ip: str, duration_seconds: int, reason: str = "Brute force detected") -> None:
	# Add with timeout
	res = _run(["ipset", "add", cfg.ipset_name, ip, "timeout", str(max(1, duration_seconds))])
	status = "ok" if res.returncode == 0 else "error"
	msg = res.stdout.strip() or res.stderr.strip()
	insert_action(int(time.time()), "block", ip, duration_seconds, status, msg or None)
	
	# Get geolocation and send notification
	if status == "ok":
		geo_info = geoip_lookup.lookup(ip)
		notification_manager.notify_ip_blocked(ip, reason, duration_seconds, geo_info)


def unblock_ip(cfg: DetectorConfig, ip: str) -> None:
	res = _run(["ipset", "del", cfg.ipset_name, ip])
	status = "ok" if res.returncode == 0 else "error"
	msg = res.stdout.strip() or res.stderr.strip()
	insert_action(int(time.time()), "unblock", ip, None, status, msg or None)


def list_blocked(cfg: DetectorConfig) -> List[str]:
	res = _run(["ipset", "list", cfg.ipset_name])
	if res.returncode != 0:
		return []
	ips: List[str] = []
	for line in res.stdout.splitlines():
		line = line.strip()
		if not line or line.startswith("Name:") or line.startswith("Type:"):
			continue
		# ipset list shows entries as: "xx.xx.xx.xx timeout ..." or just IP
		parts = line.split()
		if parts and parts[0].count(".") == 3 or ":" in parts[0]:
			ips.append(parts[0])
	return list(sorted(set(ips)))
