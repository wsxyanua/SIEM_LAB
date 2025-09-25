import os
import secrets
from functools import wraps
from typing import Optional

import bcrypt
from flask import Flask, redirect, request, session, url_for, flash, render_template_string
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

from .logger import logger


class User(UserMixin):
    """User model for authentication"""
    
    def __init__(self, id: str, username: str, password_hash: str, role: str = "admin"):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.role = role
    
    def check_password(self, password: str) -> bool:
        """Check if provided password matches hash"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))


class AuthManager:
    """Manages user authentication and authorization"""
    
    def __init__(self, app: Flask):
        self.app = app
        self.users_file = os.path.join(os.path.expanduser("~/.local/share/mini_siem"), "users.json")
        self.users: dict = {}
        
        # Setup Flask-Login
        self.login_manager = LoginManager()
        self.login_manager.init_app(app)
        self.login_manager.login_view = 'login'
        self.login_manager.login_message = 'Please log in to access this page.'
        self.login_manager.login_message_category = 'info'
        
        self._setup_login_manager()
        self._load_users()
        self._create_default_admin()
        self._setup_routes()
    
    def _setup_login_manager(self):
        """Setup login manager callbacks"""
        
        @self.login_manager.user_loader
        def load_user(user_id: str):
            return self.users.get(user_id)
    
    def _load_users(self):
        """Load users from file"""
        import json
        
        try:
            if os.path.exists(self.users_file):
                with open(self.users_file, 'r') as f:
                    user_data = json.load(f)
                    for user_id, data in user_data.items():
                        self.users[user_id] = User(
                            id=user_id,
                            username=data['username'],
                            password_hash=data['password_hash'],
                            role=data.get('role', 'admin')
                        )
                logger.info(f"Loaded {len(self.users)} users from {self.users_file}")
        except Exception as e:
            logger.error(f"Failed to load users: {e}")
    
    def _save_users(self):
        """Save users to file"""
        import json
        
        try:
            os.makedirs(os.path.dirname(self.users_file), exist_ok=True)
            user_data = {}
            for user_id, user in self.users.items():
                user_data[user_id] = {
                    'username': user.username,
                    'password_hash': user.password_hash,
                    'role': user.role
                }
            
            with open(self.users_file, 'w') as f:
                json.dump(user_data, f, indent=2)
            logger.info(f"Saved {len(self.users)} users to {self.users_file}")
        except Exception as e:
            logger.error(f"Failed to save users: {e}")
    
    def _create_default_admin(self):
        """Create default admin user if no users exist"""
        if not self.users:
            default_password = os.environ.get("SIEM_DEFAULT_PASSWORD", "admin123")
            password_hash = bcrypt.hashpw(default_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            
            admin_user = User(
                id="admin",
                username="admin",
                password_hash=password_hash,
                role="admin"
            )
            
            self.users["admin"] = admin_user
            self._save_users()
            
            logger.warning(f"Created default admin user with password: {default_password}")
            logger.warning("Please change the default password immediately!")
    
    def _setup_routes(self):
        """Setup authentication routes"""
        
        # Login page template
        login_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Mini SIEM - Login</title>
            <style>
                body { font-family: Arial, sans-serif; background: #f5f5f5; margin: 0; padding: 0; }
                .login-container { max-width: 400px; margin: 100px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                .login-header { text-align: center; margin-bottom: 30px; }
                .login-header h1 { color: #2c3e50; margin: 0; }
                .form-group { margin-bottom: 20px; }
                .form-group label { display: block; margin-bottom: 5px; color: #555; }
                .form-group input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
                .btn { width: 100%; padding: 12px; background: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
                .btn:hover { background: #2980b9; }
                .alert { padding: 10px; margin-bottom: 20px; border-radius: 4px; }
                .alert-error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
                .alert-info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
            </style>
        </head>
        <body>
            <div class="login-container">
                <div class="login-header">
                    <h1>🛡️ Mini SIEM</h1>
                    <p>Security Information & Event Management</p>
                </div>
                
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ category }}">{{ message }}</div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                
                <form method="POST">
                    <div class="form-group">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn">Login</button>
                </form>
            </div>
        </body>
        </html>
        """
        
        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            if request.method == 'POST':
                username = request.form.get('username')
                password = request.form.get('password')
                
                # Find user by username
                user = None
                for u in self.users.values():
                    if u.username == username:
                        user = u
                        break
                
                if user and user.check_password(password):
                    login_user(user)
                    logger.info(f"User {username} logged in successfully")
                    next_page = request.args.get('next')
                    return redirect(next_page or url_for('dashboard'))
                else:
                    logger.warning(f"Failed login attempt for username: {username}")
                    flash('Invalid username or password', 'error')
            
            return render_template_string(login_template)
        
        @self.app.route('/logout')
        @login_required
        def logout():
            username = current_user.username
            logout_user()
            logger.info(f"User {username} logged out")
            return redirect(url_for('login'))
        
        @self.app.route('/change-password', methods=['GET', 'POST'])
        @login_required
        def change_password():
            if request.method == 'POST':
                current_password = request.form.get('current_password')
                new_password = request.form.get('new_password')
                confirm_password = request.form.get('confirm_password')
                
                if not current_user.check_password(current_password):
                    flash('Current password is incorrect', 'error')
                elif new_password != confirm_password:
                    flash('New passwords do not match', 'error')
                elif len(new_password) < 6:
                    flash('Password must be at least 6 characters', 'error')
                else:
                    # Update password
                    new_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                    current_user.password_hash = new_hash
                    self.users[current_user.id] = current_user
                    self._save_users()
                    
                    logger.info(f"User {current_user.username} changed password")
                    flash('Password changed successfully', 'info')
                    return redirect(url_for('dashboard'))
            
            return render_template_string("""
                <!DOCTYPE html>
                <html lang=\"en\">
                <head>
                    <meta charset=\"UTF-8\">
                    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
                    <title>Change Password - Mini SIEM</title>
                    <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">
                    <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>
                    <link href=\"https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap\" rel=\"stylesheet\">
                    <style>
                        :root {
                            --bg-grad: radial-gradient(1200px 600px at 10% -10%, #cde7ff 0%, transparent 60%),
                                        radial-gradient(800px 500px at 110% 10%, #ffe1e1 0%, transparent 60%),
                                        #0f141a;
                            --card:#151b23; --text:#e6edf3; --muted:#9aa6b2; --primary:#3ea6ff; --primary-hover:#1f8de0; --danger:#ff6b6b; --border:#243142;
                            --ok:#2ecc71; --warn:#f1c40f; --weak:#ff7675;
                        }
                        body { margin:0; min-height:100vh; font-family:'Inter', system-ui, -apple-system, Segoe UI, Roboto, Arial; color:var(--text); background:var(--bg-grad); display:grid; place-items:center; }
                        .wrap { width:100%; max-width:520px; padding:24px; }
                        .card { background:linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.02)); border:1px solid var(--border); border-radius:16px; box-shadow: 0 10px 30px rgba(0,0,0,0.35); backdrop-filter: blur(8px); padding:28px; }
                        .title { margin:0; font-size:22px; font-weight:700; letter-spacing:0.2px; }
                        .subtitle { margin:6px 0 20px; color:var(--muted); font-size:14px; }
                        .alert { padding: 10px 12px; border-radius: 10px; margin-bottom: 12px; font-size: 14px; border:1px solid transparent; }
                        .alert-error { background: rgba(255,107,107,0.08); color:#ffd2d2; border-color: rgba(255,107,107,0.35); }
                        .alert-info { background: rgba(62,166,255,0.08); color:#cfe9ff; border-color: rgba(62,166,255,0.35); }
                        label { display:block; margin: 12px 0 6px; color:var(--muted); font-size:13px; font-weight:500; }
                        .row { display:flex; gap:14px; flex-wrap: wrap; }
                        .row > * { flex:1 1 260px; min-width: 0; }
                        .input-row { position:relative; margin-bottom: 6px; }
                        input[type=password], input[type=text] { width:100%; padding:12px 44px 12px 12px; border:1px solid var(--border); border-radius:10px; background:rgba(255,255,255,0.02); color:var(--text); outline:none; box-sizing: border-box; }
                        input[type=password]:focus, input[type=text]:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(62,166,255,0.15); }
                        .toggle { position:absolute; right:8px; top:50%; transform:translateY(-50%); border:none; background:transparent; cursor:pointer; color: var(--muted); padding:6px; border-radius:8px; }
                        .toggle:hover { background: rgba(255,255,255,0.06); }
                        .btn { width:100%; padding:12px; background: var(--primary); color:#0b1724; border:none; border-radius:10px; cursor:pointer; font-size:16px; font-weight:700; margin-top:10px; }
                        .btn:hover { background: var(--primary-hover); }
                        .link { display:inline-block; margin-top:12px; color: var(--primary); text-decoration:none; font-weight:600; }
                        .meta { font-size:12px; color:var(--muted); margin-top:8px; }
                        .strength { display:grid; grid-template-columns: repeat(4,1fr); gap:6px; margin-top:8px; }
                        .seg { height:8px; border-radius:4px; background:#273242; }
                        .seg.active.weak { background: var(--weak); }
                        .seg.active.med { background: var(--warn); }
                        .seg.active.strong { background: var(--ok); }
                        .policy { margin-top:8px; display:grid; gap:6px; font-size:12px; color:var(--muted); }
                        .policy .ok { color: var(--ok); }
                        .policy .bad { color: var(--weak); }
                        .hdr { display:flex; align-items:center; gap:10px; margin-bottom:4px; }
                        .badge { font-size:11px; padding:3px 8px; border-radius:999px; border:1px solid var(--border); color: var(--muted); }
                        @media (max-width: 540px) {
                            .row { flex-direction: column; }
                        }
                    </style>
                </head>
                <body>
                    <div class=\"wrap\">
                        <div class=\"card\">
                            <div class=\"hdr\">
                                <h1 class=\"title\">Change Password</h1>
                                <span class=\"badge\">Account Security</span>
                            </div>
                            <p class=\"subtitle\">Use a strong password you haven't used elsewhere.</p>

                            {% with messages = get_flashed_messages(with_categories=true) %}
                                {% if messages %}
                                    {% for category, message in messages %}
                                        <div class=\"alert alert-{{ category }}\">{{ message }}</div>
                                    {% endfor %}
                                {% endif %}
                            {% endwith %}

                            <form method=\"POST\" novalidate>
                                <label>Current Password</label>
                                <div class=\"input-row\">
                                    <input type=\"password\" name=\"current_password\" id=\"current_password\" required>
                                    <button type=\"button\" class=\"toggle\" onclick=\"togglePw('current_password')\" aria-label=\"Show/Hide\">👁️</button>
                                </div>

                                <div class=\"row\">
                                    <div>
                                        <label>New Password</label>
                                        <div class=\"input-row\">
                                            <input type=\"password\" name=\"new_password\" id=\"new_password\" required>
                                            <button type=\"button\" class=\"toggle\" onclick=\"togglePw('new_password')\" aria-label=\"Show/Hide\">👁️</button>
                                        </div>
                                        <div class=\"strength\">
                                            <div id=\"s1\" class=\"seg\"></div>
                                            <div id=\"s2\" class=\"seg\"></div>
                                            <div id=\"s3\" class=\"seg\"></div>
                                            <div id=\"s4\" class=\"seg\"></div>
                                        </div>
                                        <div class=\"policy\" id=\"policy\">
                                            <div id=\"p_len\" class=\"bad\">• At least 6 characters</div>
                                            <div id=\"p_mix\" class=\"bad\">• Mix of upper/lowercase</div>
                                            <div id=\"p_num\" class=\"bad\">• Includes a number</div>
                                            <div id=\"p_sym\" class=\"bad\">• Includes a symbol</div>
                                        </div>
                                    </div>
                                    <div>
                                        <label>Confirm New Password</label>
                                        <div class=\"input-row\">
                                            <input type=\"password\" name=\"confirm_password\" id=\"confirm_password\" required>
                                            <button type=\"button\" class=\"toggle\" onclick=\"togglePw('confirm_password')\" aria-label=\"Show/Hide\">👁️</button>
                                        </div>
                                        <div class=\"meta\" id=\"match\">Passwords must match</div>
                                    </div>
                                </div>

                                <button type=\"submit\" class=\"btn\">Save New Password</button>
                                <a class=\"link\" href=\"{{ url_for('dashboard') }}\">← Back to Dashboard</a>
                            </form>
                        </div>
                    </div>

                    <script>
                        function togglePw(id) { const el = document.getElementById(id); el.type = el.type === 'password' ? 'text' : 'password'; }
                        const np = document.getElementById('new_password');
                        const cp = document.getElementById('confirm_password');
                        const s1 = document.getElementById('s1');
                        const s2 = document.getElementById('s2');
                        const s3 = document.getElementById('s3');
                        const s4 = document.getElementById('s4');
                        const policy = { len: document.getElementById('p_len'), mix: document.getElementById('p_mix'), num: document.getElementById('p_num'), sym: document.getElementById('p_sym') };
                        const match = document.getElementById('match');
                        function evaluate(pw) {
                            const rules = { len: pw.length >= 6, mix: /[A-Z]/.test(pw) && /[a-z]/.test(pw), num: /[0-9]/.test(pw), sym: /[^A-Za-z0-9]/.test(pw) };
                            let score = 0; Object.values(rules).forEach(ok => { if (ok) score++; });
                            [s1,s2,s3,s4].forEach((seg,i)=>{ seg.className = 'seg' + (i < score ? ' active ' + (score>=4 ? 'strong' : score>=3 ? 'med' : 'weak') : ''); });
                            policy.len.className = rules.len ? 'ok' : 'bad'; policy.mix.className = rules.mix ? 'ok' : 'bad'; policy.num.className = rules.num ? 'ok' : 'bad'; policy.sym.className = rules.sym ? 'ok' : 'bad';
                        }
                        function checkMatch() { const ok = np.value && cp.value && np.value === cp.value; match.textContent = ok ? 'Passwords match' : 'Passwords must match'; match.style.color = ok ? '#2ecc71' : '#9aa6b2'; }
                        np.addEventListener('input', () => { evaluate(np.value); checkMatch(); });
                        cp.addEventListener('input', checkMatch);
                        evaluate(''); checkMatch();
                    </script>
                </body>
                </html>
            """)
    
    def require_role(self, *roles):
        """Decorator to require specific roles"""
        def decorator(f):
            @wraps(f)
            @login_required
            def decorated_function(*args, **kwargs):
                if current_user.role not in roles:
                    flash('Access denied. Insufficient privileges.', 'error')
                    return redirect(url_for('dashboard'))
                return f(*args, **kwargs)
            return decorated_function
        return decorator
    
    def create_user(self, username: str, password: str, role: str = "user") -> bool:
        """Create a new user"""
        # Check if username already exists
        for user in self.users.values():
            if user.username == username:
                return False
        
        # Create new user
        user_id = secrets.token_hex(8)
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        new_user = User(
            id=user_id,
            username=username,
            password_hash=password_hash,
            role=role
        )
        
        self.users[user_id] = new_user
        self._save_users()
        
        logger.info(f"Created new user: {username} with role: {role}")
        return True


def setup_auth(app: Flask) -> AuthManager:
    """Setup authentication for Flask app"""
    return AuthManager(app)
