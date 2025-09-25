import argparse
import sys
import time

from .config import DetectorConfig, load_config
from .db import init_db, query_actions, query_events, insert_event
from .blocker import list_blocked, unblock_ip, block_ip, ensure_firewall


def _print_rows(rows) -> None:
	if not rows:
		print("<empty>")
		return
	cols = rows[0].keys()
	print("\t".join(cols))
	for r in rows:
		print("\t".join(str(r[c]) if r[c] is not None else "" for c in cols))


def main(argv=None) -> int:
	argv = argv if argv is not None else sys.argv[1:]
	parser = argparse.ArgumentParser(prog="mini-siem")
	sub = parser.add_subparsers(dest="cmd", required=True)

	sub.add_parser("events").add_argument("--limit", type=int, default=50)
	sub.add_parser("actions").add_argument("--limit", type=int, default=50)
	sub.add_parser("blocked")
	p_unblock = sub.add_parser("unblock")
	p_unblock.add_argument("ip")
	sub.add_parser("ensure-firewall")

	p_sim = sub.add_parser("simulate", help="Generate fake failed_login events")
	p_sim.add_argument("ip", help="Source IP to simulate")
	p_sim.add_argument("--count", type=int, default=5, help="Number of failed attempts to create")
	p_sim.add_argument("--user", default="testuser", help="Username to include")
	p_sim.add_argument("--interval", type=float, default=0.0, help="Seconds to wait between events")
	p_sim.add_argument("--no-block", action="store_true", help="Do not trigger blocking even if threshold reached")

	args = parser.parse_args(argv)
	cfg = load_config()
	init_db()

	if args.cmd == "events":
		_print_rows(query_events(limit=args.limit))
		return 0
	if args.cmd == "actions":
		_print_rows(query_actions(limit=args.limit))
		return 0
	if args.cmd == "blocked":
		ips = list_blocked(cfg)
		for ip in ips:
			print(ip)
		return 0
	if args.cmd == "unblock":
		unblock_ip(cfg, args.ip)
		return 0
	if args.cmd == "ensure-firewall":
		ensure_firewall(cfg)
		return 0
	if args.cmd == "simulate":
		# Create N failed_login events and optionally block when threshold reached
		now = int(time.time())
		for i in range(args.count):
			insert_event(int(time.time()), args.ip, args.user, "failed_login", f"SIMULATED event {i+1}")
			if args.interval > 0:
				time.sleep(args.interval)
		# Decide blocking
		if not args.no_block and args.count >= cfg.failures_threshold:
			ensure_firewall(cfg)
			block_ip(cfg, args.ip, cfg.block_seconds, f"Simulated brute force ({args.count} attempts)")
		print(f"Simulated {args.count} failed_login events from {args.ip} (user={args.user}).")
		if not args.no_block and args.count >= cfg.failures_threshold:
			print(f"IP {args.ip} has been blocked for {cfg.block_seconds}s (simulated).")
		return 0
	return 1


if __name__ == "__main__":
	sys.exit(main())
