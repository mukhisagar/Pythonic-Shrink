from flask import Flask, request, redirect, jsonify, render_template, session, url_for
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import psycopg2
from psycopg2 import pool
from psycopg2.extras import DictCursor
import os
import re
import socket
import ipaddress
import hashlib
import base64
from urllib.parse import urlparse
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from contextlib import contextmanager

try:
    import requests
    _HAS_REQUESTS = True
except Exception:
    _HAS_REQUESTS = False

# Rate limit configuration
MAX_PER_WINDOW = 30                # max URLs per user per window
RATE_LIMIT_WINDOW_HOURS = 1        # window size in hours

def is_private_host(hostname):
    """Return True if hostname resolves to a private/loopback IP."""
    try:
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            ip = info[4][0]
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                    return True
            except Exception:
                continue
    except Exception:
        # DNS resolution failed — treat as non-private (validation will fail elsewhere)
        return False
    return False

def is_valid_url(long_url, perform_head_check=True):
    """
    Basic validation:
      - correct scheme (http/https)
      - has hostname
      - hostname doesn't resolve to private/loopback addresses
      - optional: perform a quick HEAD to ensure reachable (best-effort)
    Returns (True, None) or (False, "reason")
    """
    if not long_url:
        return False, "Empty URL"

    parsed = urlparse(long_url)
    if parsed.scheme not in ('http', 'https'):
        return False, "URL must start with http:// or https://"

    host = parsed.hostname
    if not host:
        return False, "URL has no hostname"

    # disallow localhost and local network addresses
    if host in ("localhost", "127.0.0.1") or is_private_host(host):
        return False, "URL resolves to a local or private address"

    # optional quick HEAD check to see if it's reachable
    if perform_head_check and _HAS_REQUESTS:
        try:
            resp = requests.head(long_url, allow_redirects=True, timeout=3)
            # treat 4xx/5xx as bad (some sites block HEAD; fall back to GET in that case)
            if resp.status_code >= 400:
                # try a shallow GET if HEAD failed
                resp = requests.get(long_url, stream=True, allow_redirects=True, timeout=5)
            if resp.status_code >= 400:
                return False, f"Destination returned HTTP {resp.status_code}"
        except requests.RequestException:
            # network error; be conservative and reject
            return False, "Destination is not reachable"
    # If requests isn't available, skip the reachability check but keep host checks
    return True, None

def can_shorten(user_id):
    """
    Enforce rate limit using the database: count how many short URLs this user
    created in the last RATE_LIMIT_WINDOW_HOURS. Returns (True, None) or (False, msg).
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM url_mapping WHERE user_id = %s AND created_at >= (CURRENT_TIMESTAMP - INTERVAL '%s hour')",
            (user_id, RATE_LIMIT_WINDOW_HOURS)
        )
        count = cursor.fetchone()[0]
        conn.close()
        if count >= MAX_PER_WINDOW:
            return False, f"Rate limit exceeded: max {MAX_PER_WINDOW} URLs per {RATE_LIMIT_WINDOW_HOURS} hour(s)."
        return True, None
    except Exception as e:
        # On DB error, deny to be safe (or alternatively allow)
        return False, "Rate limit check failed; try again later"

# Configuration - load from environment
class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-please-change")
    DB_DSN = os.environ.get("DB_CONFIG")  # e.g. postgres://user:pass@host:5432/dbname
    CUSTOM_HOST_URL = os.environ.get("CUSTOM_HOST_URL", "https://pythonic-shrink.onrender.com/")
    API_KEY = os.environ.get("API_KEY", "")

app = Flask(__name__)
app.config.from_object(Config)

# init a simple connection pool (optional)
_db_pool = None
if app.config['DB_DSN']:
    try:
        _db_pool = psycopg2.pool.SimpleConnectionPool(1, 10, dsn=app.config['DB_DSN'])
    except Exception:
        _db_pool = None

def get_db_connection():
    """Return a psycopg2 connection (from pool if available). Caller must close."""
    if _db_pool:
        return _db_pool.getconn()
    if app.config['DB_DSN']:
        return psycopg2.connect(app.config['DB_DSN'])
    raise RuntimeError("Database not configured. Set DB_CONFIG environment variable.")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=DictCursor)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if user:
        return User(id=user['id'], username=user['username'])
    return None

# Function to generate a short URL
def generate_short_url(long_url):
     hash_object = hashlib.sha256(long_url.encode())
     short_hash = base64.urlsafe_b64encode(hash_object.digest())[:6].decode()
     return short_hash

# Serve the HTML form
@app.route('/')
@login_required
def home():
     return render_template('index.html')

# Handle URL shortening
@app.route('/shorten', methods=['POST'])
@login_required
def shorten_url():
    long_url = request.form.get('long_url', '').strip()
    custom_short_url = request.form.get('custom_short_url', '').strip()
    expiration_date = request.form.get('expiration_date', None)

    # 1) Rate limiting
    allowed, msg = can_shorten(current_user.id)
    if not allowed:
        return render_template('index.html', error=msg), 429

    # 2) Validate URL
    ok, reason = is_valid_url(long_url)
    if not ok:
        return render_template('index.html', error=f"Invalid URL: {reason}"), 400

    # 3) Validate custom short URL (if provided)
    if custom_short_url:
        if not re.match(r'^[A-Za-z0-9_-]{3,40}$', custom_short_url):
            return render_template('index.html', error="Custom alias may contain only letters, numbers, - and _. (3-40 chars)"), 400
        # ensure uniqueness
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        cursor.execute("SELECT 1 FROM url_mapping WHERE short_url = %s", (custom_short_url,))
        if cursor.fetchone():
            conn.close()
            return render_template('index.html', error="Custom short URL already in use, choose another"), 409
        short_url = custom_short_url
    else:
        # generate a collision-resistant short code
        # try a few times in case of collision
        short_url = None
        attempts = 0
        while attempts < 5 and not short_url:
            candidate = generate_short_url(long_url + str(datetime.utcnow().timestamp()) + os.urandom(4).hex())
            # keep candidate short (6-10 chars)
            candidate = candidate[:8]
            conn = get_db_connection()
            cursor = conn.cursor(cursor_factory=DictCursor)
            cursor.execute("SELECT 1 FROM url_mapping WHERE short_url = %s", (candidate,))
            if not cursor.fetchone():
                short_url = candidate
            conn.close()
            attempts += 1
        if not short_url:
            return render_template('index.html', error="Could not generate a unique short URL, please try again"), 500

    # 4) Save mapping
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        if expiration_date:
            # expect ISO date from form; store as timestamptz in DB; adjust as needed
            cursor.execute(
                "INSERT INTO url_mapping (short_url, long_url, user_id, expiration_date, created_at) VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)",
                (short_url, long_url, current_user.id, expiration_date)
            )
        else:
            cursor.execute(
                "INSERT INTO url_mapping (short_url, long_url, user_id, created_at) VALUES (%s, %s, %s, CURRENT_TIMESTAMP)",
                (short_url, long_url, current_user.id)
            )
        conn.commit()
        conn.close()
        full_short = app.config['CUSTOM_HOST_URL'].rstrip('/') + '/' + short_url
        return render_template('shortened.html', short_url=full_short)
    except Exception as e:
        return render_template('index.html', error=f"Database error: {e}"), 500


# Redirect shortened URLs
@app.route('/<short_url>', methods=['GET'])
def redirect_url(short_url):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=DictCursor)

    # Check if the URL exists and is not expired
    cursor.execute(
        "SELECT long_url, expiration_date FROM url_mapping WHERE short_url = %s",
        (short_url,)
    )
    entry = cursor.fetchone()
    if entry:
        if entry['expiration_date'] and entry['expiration_date'] < cursor.execute("SELECT CURRENT_TIMESTAMP"):
            conn.close()
            return "Error: This shortened URL has expired.", 410  # HTTP 410 Gone

        # Update the clicks and last_accessed columns
        cursor.execute(
            "UPDATE url_mapping SET clicks = clicks + 1, last_accessed = CURRENT_TIMESTAMP WHERE short_url = %s",
            (short_url,)
        )
        conn.commit()
        conn.close()
        return redirect(entry['long_url'])

    conn.close()
    return "Error: URL not found", 404

@app.route('/analytics/<short_url>', methods=['GET'])
def analytics(short_url):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)

        # Fetch analytics data for the given short URL
        cursor.execute(
            "SELECT long_url, clicks, created_at, last_accessed FROM url_mapping WHERE short_url = %s",
            (short_url,)
        )
        entry = cursor.fetchone()
        conn.close()

        if entry:
            return render_template('analytics.html', data=entry)
        else:
            return "Error: URL not found", 404
    except Exception as e:
        return f"Database error: {e}", 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate username and password
        if not re.match("^[a-zA-Z0-9_]+$", username):
            return "Error: Username can only contain letters, numbers, and underscores.", 400
        if len(password) < 8 or not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(r'[0-9]', password):
            return "Error: Password must be at least 8 characters long and include an uppercase letter, a lowercase letter, and a number.", 400

        # Hash the password
        password_hash = generate_password_hash(password)

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, password_hash))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))  # Redirect to the login page after successful registration
        except Exception as e:
            return f"Error: {e}", 500

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Check if there are any users in the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    conn.close()

    # If no users exist, redirect to the register page
    if user_count == 0:
        return redirect(url_for('register'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            login_user(User(id=user['id'], username=user['username']))
            return redirect(url_for('home'))  # Redirect to the homepage
        else:
            return "Invalid username or password."

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()  # Use Flask-Login's logout
    # show a friendly page with a button to log back in
    return render_template('logout.html')

@app.route('/preview/<short_url>', methods=['GET'])
def preview_url(short_url):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=DictCursor)
    cursor.execute(
        "SELECT long_url, expiration_date FROM url_mapping WHERE short_url = %s",
        (short_url,)
    )
    entry = cursor.fetchone()
    conn.close()
    if entry:
        # Check expiration
        # (You may want to check expiration here as in your redirect logic)
        return render_template('preview.html', long_url=entry['long_url'], short_url=short_url)
    return "Error: URL not found", 404

@app.route('/api/shorten', methods=['POST'])
def api_shorten():
    """
    JSON API: POST /api/shorten
    Body: { "long_url": "...", "custom_short_url": "...", "expiration_date": "YYYY-MM-DD" }
    Auth: either logged-in user (Flask-Login) OR header X-API-KEY matching env API_KEY.
    Response: JSON { "short_url": "...", "full_short_url": "https://...", "created": "iso" }
    """
    data = request.get_json(silent=True) or {}
    long_url = (data.get('long_url') or '').strip()
    custom_short_url = (data.get('custom_short_url') or '').strip()
    expiration_date = data.get('expiration_date')  # optional ISO date string

    # authentication: prefer logged-in user, else API key
    if current_user and getattr(current_user, 'is_authenticated', False):
        user_id = current_user.id
    else:
        api_key = request.headers.get('X-API-KEY')
        if not api_key or api_key != os.environ.get('API_KEY'):
            return jsonify({"error": "Authentication required: login or provide X-API-KEY"}), 401
        try:
            user_id = int(os.environ.get('API_USER_ID', 0))
        except Exception:
            user_id = 0

    # rate limit
    allowed, msg = can_shorten(user_id)
    if not allowed:
        return jsonify({"error": msg}), 429

    # validate URL
    ok, reason = is_valid_url(long_url)
    if not ok:
        return jsonify({"error": f"Invalid URL: {reason}"}), 400

    # validate custom alias
    conn = None
    try:
        if custom_short_url:
            if not re.match(r'^[A-Za-z0-9_-]{3,40}$', custom_short_url):
                return jsonify({"error": "Custom alias may contain only letters, numbers, - and _. (3-40 chars)"}), 400
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=DictCursor)
            cur.execute("SELECT 1 FROM url_mapping WHERE short_url = %s", (custom_short_url,))
            if cur.fetchone():
                return jsonify({"error": "Custom short URL already in use"}), 409
            short_url = custom_short_url
        else:
            short_url = None
            attempts = 0
            while attempts < 5 and not short_url:
                candidate = generate_short_url(long_url + str(datetime.utcnow().timestamp()) + os.urandom(4).hex())
                candidate = candidate[:8]
                conn = get_db_connection()
                cur = conn.cursor(cursor_factory=DictCursor)
                cur.execute("SELECT 1 FROM url_mapping WHERE short_url = %s", (candidate,))
                if not cur.fetchone():
                    short_url = candidate
                conn.close()
                attempts += 1
            if not short_url:
                return jsonify({"error": "Could not generate a unique short URL, try again"}), 500

        # persist mapping
        conn = get_db_connection()
        cur = conn.cursor()
        if expiration_date:
            cur.execute(
                "INSERT INTO url_mapping (short_url, long_url, user_id, expiration_date, created_at) VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP)",
                (short_url, long_url, user_id, expiration_date)
            )
        else:
            cur.execute(
                "INSERT INTO url_mapping (short_url, long_url, user_id, created_at) VALUES (%s, %s, %s, CURRENT_TIMESTAMP)",
                (short_url, long_url, user_id)
            )
        conn.commit()
        full_short = app.config['CUSTOM_HOST_URL'].rstrip('/') + '/' + short_url
        return jsonify({
            "short_url": short_url,
            "full_short_url": full_short,
            "long_url": long_url,
            "created": datetime.utcnow().isoformat() + "Z"
        }), 201
    except Exception as e:
        return jsonify({"error": f"Database error: {e}"}), 500
    finally:
        try:
            if conn:
                conn.close()
        except Exception:
            pass

@contextmanager
def db_cursor(dict_cursor=False):
    conn = get_db_connection()
    try:
        cur = conn.cursor(cursor_factory=DictCursor) if dict_cursor else conn.cursor()
        yield conn, cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        try:
            if _db_pool:
                _db_pool.putconn(conn)
            else:
                conn.close()
        except Exception:
            pass
# Run the Flask application
if __name__ == '__main__':
     app.run(debug=True)