import json
import os
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from flask import Flask, jsonify, render_template_string, request
from flask_socketio import SocketIO, emit
from flask_login import login_required, current_user

from .blocker import list_blocked, unblock_ip
from .config import load_config
from .db import query_actions, query_events
from .logger import logger
from .web_auth import setup_auth


# HTML template for dashboard
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mini SIEM Dashboard</title>
    <style>
        :root {
            --bg: #f5f5f5;
            --card: #ffffff;
            --text: #2c3e50;
            --muted: #7f8c8d;
            --primary: #3498db;
            --primary-hover: #2980b9;
            --danger: #e74c3c;
            --danger-hover: #c0392b;
            --shadow: rgba(0,0,0,0.08);
            --table-border: #ddd;
        }
        .dark {
            --bg: #0f141a;
            --card: #151b23;
            --text: #e6edf3;
            --muted: #9aa6b2;
            --primary: #3ea6ff;
            --primary-hover: #1f8de0;
            --danger: #ff6b6b;
            --danger-hover: #e85a5a;
            --shadow: rgba(0,0,0,0.35);
            --table-border: #2a3441;
        }
        body { font-family: Arial, sans-serif; margin: 0; background-color: var(--bg); color: var(--text); }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 8px var(--shadow); }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: var(--card); padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px var(--shadow); }
        .stat-value { font-size: 2em; font-weight: bold; color: var(--danger); }
        .stat-label { color: var(--muted); margin-top: 5px; }
        .section { background: var(--card); padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px var(--shadow); margin-bottom: 20px; }
        .charts { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; }
        .charts-card { background: var(--card); border: 1px solid var(--table-border); border-radius: 8px; box-shadow: 0 2px 8px var(--shadow); padding: 12px; height: 180px; display: flex; flex-direction: column; }
        .charts-card canvas { flex: 1; width: 100% !important; height: 100% !important; }
        .table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        .table th, .table td { padding: 10px; text-align: left; border-bottom: 1px solid var(--table-border); }
        .table th { background-color: rgba(0,0,0,0.03); font-weight: bold; }
        .blocked-ip { color: var(--danger); font-weight: bold; }
        .btn { background: var(--primary); color: white; border: none; padding: 8px 14px; border-radius: 6px; cursor: pointer; }
        .btn:hover { background: var(--primary-hover); }
        .refresh-btn { background: var(--primary); }
        .refresh-btn:hover { background: var(--primary-hover); }
        .status-indicator { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 5px; }
        .status-online { background: #27ae60; }
        .status-offline { background: var(--danger); }
        .navbar { position: sticky; top: 0; z-index: 10; background: #2c3e50; color: white; padding: 10px 20px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 8px var(--shadow); }
        .navbar a { color: white; text-decoration: none; margin: 0 10px; }
        .navbar a:hover { text-decoration: underline; }
        .unblock-btn { background: var(--danger); color: white; border: none; padding: 6px 10px; border-radius: 4px; cursor: pointer; font-size: 12px; }
        .unblock-btn:hover { background: var(--danger-hover); }
        .toolbar { display: flex; gap: 10px; align-items: center; margin-top: 10px; }
        .input { padding: 8px 10px; border: 1px solid var(--table-border); border-radius: 6px; background: transparent; color: var(--text); }
        .input::placeholder { color: var(--muted); }
        .pagination { display: flex; gap: 8px; align-items: center; margin-top: 10px; }
        .page-btn { padding: 6px 10px; border: 1px solid var(--table-border); border-radius: 6px; background: transparent; color: var(--text); cursor: pointer; }
        .page-btn[disabled] { opacity: 0.5; cursor: not-allowed; }
        .toast { position: fixed; right: 16px; bottom: 16px; background: var(--card); color: var(--text); padding: 12px 16px; border-radius: 8px; box-shadow: 0 2px 8px var(--shadow); display: none; }
        @media (max-width: 768px) { .container { padding: 10px; } .stats { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <div class="navbar">
        <div>
            <a href="{{ url_for('dashboard') }}">🛡️ Mini SIEM</a>
            <a href="{{ url_for('dashboard') }}">Dashboard</a>
            <a href="{{ url_for('change_password') }}">Settings</a>
        </div>
        <div>
            <button id="themeToggle" class="btn" aria-label="Toggle dark mode">Toggle Theme</button>
            <span style="margin: 0 8px;">|</span>
            <span>Welcome, {{ current_user.username }}</span>
            <a style="margin-left: 10px;" href="{{ url_for('logout') }}">Logout</a>
        </div>
    </div>
    
    <div class="container">
        <div class="header">
            <h1>🛡️ Mini SIEM Dashboard</h1>
            <p>Real-time SSH Brute Force Detection & Response</p>
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-value" id="blocked-count">{{ blocked_count }}</div>
                <div class="stat-label">Currently Blocked IPs</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="events-24h">{{ events_24h }}</div>
                <div class="stat-label">Events (24h)</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="actions-24h">{{ actions_24h }}</div>
                <div class="stat-label">Actions (24h)</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="last-update">{{ last_update }}</div>
                <div class="stat-label">Last Update</div>
            </div>
        </div>

        <div class="section">
            <h2 style="margin-top:0">📈 Overview</h2>
            <div class="charts">
                <div class="charts-card">
                    <canvas id="eventsSparkline"></canvas>
                    <div class="stat-label" style="text-align:center;margin-top:8px;">Events last 24h</div>
                </div>
                <div class="charts-card">
                    <canvas id="actionsDonut"></canvas>
                    <div class="stat-label" style="text-align:center;margin-top:8px;">Action status distribution</div>
                </div>
            </div>
        </div>

        <div class="section">
            <div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;">
                <h2 style="margin:0;">🚫 Blocked IPs</h2>
                <div class="toolbar">
                    <input id="searchInput" class="input" type="text" placeholder="Search IP or CIDR..." aria-label="Search blocked IPs" />
                    <select id="pageSize" class="input" aria-label="Rows per page">
                        <option value="10">10</option>
                        <option value="25">25</option>
                        <option value="50">50</option>
                    </select>
                    <button class="refresh-btn btn" onclick="refreshData()">Refresh</button>
                </div>
            </div>
            <table class="table">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="blocked-table"></tbody>
            </table>
            <div class="pagination">
                <button id="prevPage" class="page-btn">Prev</button>
                <span id="pageInfo"></span>
                <button id="nextPage" class="page-btn">Next</button>
            </div>
        </div>

        <div class="section">
            <h2>📊 Recent Security Events</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>IP</th>
                        <th>Username</th>
                        <th>Reason</th>
                    </tr>
                </thead>
                <tbody id="events-table">
                    {% for event in recent_events %}
                    <tr>
                        <td>{{ event.timestamp }}</td>
                        <td>{{ event.src_ip }}</td>
                        <td>{{ event.username or 'N/A' }}</td>
                        <td>{{ event.reason }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>⚡ Recent Actions</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Action</th>
                        <th>IP</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="actions-table">
                    {% for action in recent_actions %}
                    <tr>
                        <td>{{ action.timestamp }}</td>
                        <td>{{ action.action }}</td>
                        <td>{{ action.src_ip or 'N/A' }}</td>
                        <td>
                            <span class="status-indicator {{ 'status-online' if action.status == 'ok' else 'status-offline' }}"></span>
                            {{ action.status }}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>

    <div id="toast" class="toast" role="status" aria-live="polite"></div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.js"></script>
    <script>
        // Data from backend
        const BLOCKED_IPS = {{ blocked_ips | tojson }};
        const EVENTS_24H_SERIES = {{ events_24h_series | tojson }};
        const ACTIONS_STATUS = {{ actions_status | tojson }};

        // Theme persistence
        const root = document.documentElement;
        const themeToggle = document.getElementById('themeToggle');
        function applyTheme(theme) {
            if (theme === 'dark') { document.body.classList.add('dark'); }
            else { document.body.classList.remove('dark'); }
            localStorage.setItem('siem_theme', theme);
        }
        function initTheme() {
            const saved = localStorage.getItem('siem_theme');
            if (saved) return applyTheme(saved);
            const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
            applyTheme(prefersDark ? 'dark' : 'light');
        }
        themeToggle.addEventListener('click', () => {
            const isDark = document.body.classList.contains('dark');
            applyTheme(isDark ? 'light' : 'dark');
            showToast('Theme: ' + (isDark ? 'Light' : 'Dark'));
        });
        initTheme();

        // Toast
        const toast = document.getElementById('toast');
        let toastTimer;
        function showToast(msg) {
            toast.textContent = msg;
            toast.style.display = 'block';
            clearTimeout(toastTimer);
            toastTimer = setTimeout(() => toast.style.display = 'none', 2500);
        }

        // Charts
        function renderCharts() {
            const ctx1 = document.getElementById('eventsSparkline').getContext('2d');
            new Chart(ctx1, {
                type: 'line',
                data: {
                    labels: Array.from({length: 24}, (_, i) => i - 23).map(h => h === 0 ? 'now' : `${h}h`),
                    datasets: [{
                        data: EVENTS_24H_SERIES,
                        borderColor: getComputedStyle(document.body).getPropertyValue('--primary').trim() || '#3498db',
                        backgroundColor: 'transparent',
                        tension: 0.3,
                        pointRadius: 0,
                        borderWidth: 2,
                        fill: false,
                    }]
                },
                options: {
                    plugins: { legend: { display: false } },
                    scales: { x: { display: false }, y: { display: false } },
                    responsive: true,
                    maintainAspectRatio: false
                }
            });

            const ctx2 = document.getElementById('actionsDonut').getContext('2d');
            const ok = ACTIONS_STATUS.ok || 0; const error = ACTIONS_STATUS.error || 0; const other = ACTIONS_STATUS.other || 0;
            new Chart(ctx2, {
                type: 'doughnut',
                data: {
                    labels: ['ok', 'error', 'other'],
                    datasets: [{ data: [ok, error, other], backgroundColor: ['#27ae60', '#e74c3c', '#95a5a6'] }]
                },
                options: { plugins: { legend: { position: 'bottom' } }, cutout: '65%', maintainAspectRatio: false }
            });
        }

        // Blocked IPs table with search + pagination
        const searchInput = document.getElementById('searchInput');
        const pageSizeSel = document.getElementById('pageSize');
        const blockedTable = document.getElementById('blocked-table');
        const prevBtn = document.getElementById('prevPage');
        const nextBtn = document.getElementById('nextPage');
        const pageInfo = document.getElementById('pageInfo');
        let state = { page: 1, pageSize: 10, query: '' };

        function filterData() {
            const q = state.query.trim().toLowerCase();
            if (!q) return [...BLOCKED_IPS];
            return BLOCKED_IPS.filter(ip => ip.toLowerCase().includes(q));
        }
        function renderTable() {
            const data = filterData();
            const total = data.length;
            const pages = Math.max(1, Math.ceil(total / state.pageSize));
            if (state.page > pages) state.page = pages;
            const start = (state.page - 1) * state.pageSize;
            const end = start + state.pageSize;
            const rows = data.slice(start, end);
            blockedTable.innerHTML = rows.map(ip => `
                <tr>
                    <td class=\"blocked-ip\">${ip}</td>
                    <td>
                        <span class=\"status-indicator status-online\"></span>Blocked
                        <button class=\"unblock-btn\" onclick=\"unblockIP('${ip}')\">Unblock</button>
                    </td>
                </tr>
            `).join('');
            pageInfo.textContent = `Page ${state.page} / ${pages} — ${total} items`;
            prevBtn.disabled = state.page <= 1;
            nextBtn.disabled = state.page >= pages;
        }
        searchInput.addEventListener('input', (e) => { state.query = e.target.value; state.page = 1; renderTable(); });
        pageSizeSel.addEventListener('change', (e) => { state.pageSize = parseInt(e.target.value, 10); state.page = 1; renderTable(); });
        prevBtn.addEventListener('click', () => { if (state.page > 1) { state.page--; renderTable(); }});
        nextBtn.addEventListener('click', () => { state.page++; renderTable(); });

        // Initialize table & charts
        renderTable();
        renderCharts();

        // Socket.IO
        const socket = io();
        function refreshData() { location.reload(); }
        function unblockIP(ip) {
            if (confirm('Are you sure you want to unblock ' + ip + '?')) {
                fetch('/api/unblock/' + ip, { method: 'POST' })
                    .then(r => r.json())
                    .then(d => { if (d.status === 'success') { showToast('Unblocked ' + ip); refreshData(); } else { showToast('Error: ' + d.error); } })
                    .catch(err => showToast('Error: ' + err));
            }
        }
        socket.on('new_event', function(data) { /* future incremental updates */ });
        socket.on('new_block', function(data) { showToast('New block: ' + (data.ip || 'IP')); refreshData(); });
        setInterval(refreshData, 30000);
    </script>
</body>
</html>
"""


class WebDashboard:
	"""Web dashboard for SIEM monitoring"""
	
	def __init__(self, host: str = "0.0.0.0", port: int = 5000):
		self.app = Flask(__name__)
		self.app.secret_key = os.environ.get('SIEM_SECRET_KEY', 'your-secret-key-change-this')
		self.host = host
		self.port = port
		self.cfg = load_config()
		
		# Setup SocketIO for real-time updates
		self.socketio = SocketIO(self.app, cors_allowed_origins="*")
		
		# Setup authentication
		self.auth_manager = setup_auth(self.app)
		
		self._setup_routes()
		self._setup_socketio()
	
	def _setup_routes(self):
		"""Setup Flask routes"""
		
		@self.app.route('/')
		@login_required
		def dashboard():
			"""Main dashboard page"""
			try:
				# Get recent data
				blocked_ips = list_blocked(self.cfg)
				recent_events = self._get_recent_events(limit=10)
				recent_actions = self._get_recent_actions(limit=10)
				
				# Calculate stats
				events_24h = self._count_events_24h()
				actions_24h = self._count_actions_24h()
				
				# Series for charts
				events_series = self._series_events_last_24h()
				actions_status = self._actions_status_counts()
				
				return render_template_string(
					DASHBOARD_TEMPLATE,
					blocked_count=len(blocked_ips),
					events_24h=events_24h,
					actions_24h=actions_24h,
					last_update=datetime.now().strftime("%H:%M:%S"),
					blocked_ips=blocked_ips,
					recent_events=recent_events,
					recent_actions=recent_actions,
					events_24h_series=events_series,
					actions_status=actions_status
				)
			except Exception as e:
				logger.error(f"Dashboard error: {e}")
				return f"Error loading dashboard: {e}", 500
		
		@self.app.route('/api/stats')
		@login_required
		def api_stats():
			"""API endpoint for statistics"""
			try:
				blocked_ips = list_blocked(self.cfg)
				return jsonify({
					"blocked_count": len(blocked_ips),
					"events_24h": self._count_events_24h(),
					"actions_24h": self._count_actions_24h(),
					"last_update": datetime.now().isoformat()
				})
			except Exception as e:
				logger.error(f"API stats error: {e}")
				return jsonify({"error": str(e)}), 500
		
		@self.app.route('/api/events')
		@login_required
		def api_events():
			"""API endpoint for events"""
			try:
				limit = request.args.get('limit', 50, type=int)
				events = self._get_recent_events(limit)
				return jsonify([{
					"timestamp": datetime.fromtimestamp(e["ts"]).isoformat(),
					"src_ip": e["src_ip"],
					"username": e["username"],
					"reason": e["reason"]
				} for e in events])
			except Exception as e:
				logger.error(f"API events error: {e}")
				return jsonify({"error": str(e)}), 500
		
		@self.app.route('/api/actions')
		@login_required
		def api_actions():
			"""API endpoint for actions"""
			try:
				limit = request.args.get('limit', 50, type=int)
				actions = self._get_recent_actions(limit)
				return jsonify([{
					"timestamp": datetime.fromtimestamp(a["ts"]).isoformat(),
					"action": a["action"],
					"src_ip": a["src_ip"],
					"status": a["status"],
					"message": a["message"]
				} for a in actions])
			except Exception as e:
				logger.error(f"API actions error: {e}")
				return jsonify({"error": str(e)}), 500
		
		@self.app.route('/api/blocked')
		@login_required
		def api_blocked():
			"""API endpoint for blocked IPs"""
			try:
				blocked_ips = list_blocked(self.cfg)
				return jsonify({"blocked_ips": blocked_ips})
			except Exception as e:
				logger.error(f"API blocked error: {e}")
				return jsonify({"error": str(e)}), 500
		
		@self.app.route('/api/unblock/<ip>', methods=['POST'])
		@login_required
		def api_unblock(ip):
			"""API endpoint to unblock IP"""
			try:
				from .blocker import unblock_ip
				unblock_ip(self.cfg, ip)
				logger.info(f"IP {ip} unblocked via API")
				return jsonify({"status": "success", "message": f"IP {ip} unblocked"})
			except Exception as e:
				logger.error(f"API unblock error: {e}")
				return jsonify({"error": str(e)}), 500
	
	def _setup_socketio(self):
		"""Setup SocketIO events for real-time updates"""
		
		@self.socketio.on('connect')
		def handle_connect():
			logger.info(f"Client connected: {request.sid}")
		
		@self.socketio.on('disconnect')
		def handle_disconnect():
			logger.info(f"Client disconnected: {request.sid}")
	
	def emit_new_event(self, event_data):
		"""Emit new event to connected clients"""
		self.socketio.emit('new_event', event_data)
	
	def emit_new_block(self, block_data):
		"""Emit new block event to connected clients"""
		self.socketio.emit('new_block', block_data)
	
	def _get_recent_events(self, limit: int = 10) -> List[Dict]:
		"""Get recent events with formatted timestamps"""
		events = query_events(limit)
		return [{
			"timestamp": datetime.fromtimestamp(e["ts"]).strftime("%Y-%m-%d %H:%M:%S"),
			"src_ip": e["src_ip"],
			"username": e["username"],
			"reason": e["reason"]
		} for e in events]
	
	def _get_recent_actions(self, limit: int = 10) -> List[Dict]:
		"""Get recent actions with formatted timestamps"""
		actions = query_actions(limit)
		return [{
			"timestamp": datetime.fromtimestamp(a["ts"]).strftime("%Y-%m-%d %H:%M:%S"),
			"action": a["action"],
			"src_ip": a["src_ip"],
			"status": a["status"],
			"message": a["message"]
		} for a in actions]
	
	def _count_events_24h(self) -> int:
		"""Count events in last 24 hours"""
		try:
			from .db import _connect
			conn = _connect()
			try:
				cutoff = int(time.time()) - 86400  # 24 hours ago
				cur = conn.execute(
					"SELECT COUNT(*) as count FROM events WHERE ts >= ?",
					(cutoff,)
				)
				result = cur.fetchone()
				return result["count"] if result else 0
			finally:
				conn.close()
		except Exception:
			return 0
	
	def _count_actions_24h(self) -> int:
		"""Count actions in last 24 hours"""
		try:
			from .db import _connect
			conn = _connect()
			try:
				cutoff = int(time.time()) - 86400  # 24 hours ago
				cur = conn.execute(
					"SELECT COUNT(*) as count FROM actions WHERE ts >= ?",
					(cutoff,)
				)
				result = cur.fetchone()
				return result["count"] if result else 0
			finally:
				conn.close()
		except Exception:
			return 0
	
	def _series_events_last_24h(self) -> List[int]:
		"""Return 24-length series of event counts per hour (oldest to newest)."""
		try:
			from .db import _connect
			conn = _connect()
			try:
				now = int(time.time())
				start = now - 24 * 3600
				# Fetch all counts grouped by hour
				cur = conn.execute(
					"""
					SELECT ((ts / 3600) * 3600) as hour_bucket, COUNT(*) as c
					FROM events
					WHERE ts >= ?
					GROUP BY hour_bucket
					ORDER BY hour_bucket ASC
					""",
					(start,)
				)
				rows = cur.fetchall()
				bucket_to_count = { int(r["hour_bucket"]): int(r["c"]) for r in rows }
				series: List[int] = []
				for i in range(23, -1, -1):
					bucket = ((now - i * 3600) // 3600) * 3600
					series.append(bucket_to_count.get(bucket, 0))
				return series
			finally:
				conn.close()
		except Exception:
			return [0] * 24
	
	def _actions_status_counts(self) -> Dict[str, int]:
		"""Return counts of action statuses (ok, error, other)."""
		try:
			from .db import _connect
			conn = _connect()
			try:
				cur = conn.execute(
					"SELECT status, COUNT(*) as c FROM actions GROUP BY status"
				)
				rows = cur.fetchall()
				result = { 'ok': 0, 'error': 0, 'other': 0 }
				for r in rows:
					status = (r["status"] or "other").lower()
					if status not in result:
						status = 'other'
					result[status] += int(r["c"])
				return result
			finally:
				conn.close()
		except Exception:
			return { 'ok': 0, 'error': 0, 'other': 0 }
	
	def run(self, debug: bool = False):
		"""Run the web dashboard"""
		logger.info(f"Starting web dashboard on {self.host}:{self.port}")
		self.socketio.run(self.app, host=self.host, port=self.port, debug=debug)


def run_dashboard(host: str = "0.0.0.0", port: int = 5000, debug: bool = False):
	"""Run the web dashboard"""
	dashboard = WebDashboard(host, port)
	dashboard.run(debug)
