import os
import sqlite3
import time
from typing import List, Optional

from .config import DB_PATH_DEFAULT, ensure_data_dir


SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts INTEGER NOT NULL,
	src_ip TEXT NOT NULL,
	username TEXT,
	reason TEXT NOT NULL,
	raw TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events (src_ip);

CREATE TABLE IF NOT EXISTS actions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ts INTEGER NOT NULL,
	action TEXT NOT NULL,
	src_ip TEXT,
	duration_sec INTEGER,
	status TEXT NOT NULL,
	message TEXT
);

CREATE INDEX IF NOT EXISTS idx_actions_ts ON actions (ts);
"""


def _connect(db_path: Optional[str] = None) -> sqlite3.Connection:
	ensure_data_dir()
	conn = sqlite3.connect(db_path or DB_PATH_DEFAULT)
	conn.row_factory = sqlite3.Row
	return conn


def init_db(db_path: Optional[str] = None) -> None:
	conn = _connect(db_path)
	try:
		conn.executescript(SCHEMA)
		conn.commit()
	finally:
		conn.close()


def insert_event(ts: Optional[int], src_ip: str, username: Optional[str], reason: str, raw: Optional[str]) -> None:
	conn = _connect()
	try:
		conn.execute(
			"INSERT INTO events (ts, src_ip, username, reason, raw) VALUES (?, ?, ?, ?, ?)",
			(ts or int(time.time()), src_ip, username, reason, raw),
		)
		conn.commit()
	finally:
		conn.close()


def insert_action(ts: Optional[int], action: str, src_ip: Optional[str], duration_sec: Optional[int], status: str, message: Optional[str]) -> None:
	conn = _connect()
	try:
		conn.execute(
			"INSERT INTO actions (ts, action, src_ip, duration_sec, status, message) VALUES (?, ?, ?, ?, ?, ?)",
			(ts or int(time.time()), action, src_ip, duration_sec, status, message),
		)
		conn.commit()
	finally:
		conn.close()


def query_events(limit: int = 50) -> List[sqlite3.Row]:
	conn = _connect()
	try:
		cur = conn.execute("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,))
		return cur.fetchall()
	finally:
		conn.close()


def query_actions(limit: int = 50) -> List[sqlite3.Row]:
	conn = _connect()
	try:
		cur = conn.execute("SELECT * FROM actions ORDER BY ts DESC LIMIT ?", (limit,))
		return cur.fetchall()
	finally:
		conn.close()
