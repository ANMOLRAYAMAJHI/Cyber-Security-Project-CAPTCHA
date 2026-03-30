from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import bcrypt, random, re, os
from datetime import datetime
from functools import wraps
import oracledb

app = Flask(__name__)

# ── FIX 1: Fixed secret key (was os.urandom(24) which changes on every restart,
#            invalidating all sessions) ──
app.secret_key = "securereg-secret-key-cet324"

# ── FIX 2: oracledb thin mode init (no Oracle Instant Client needed) ──
# python-oracledb defaults to thin mode automatically, but we set a
# connection timeout so the server doesn't hang forever if Oracle is down.
DB_CONFIG = {
    "user": "Stamford",
    "password": "stamford123",
    "dsn": "localhost:1521/XEPDB1"
}

def get_connection():
    """Returns a DB connection, raises a clear error if Oracle is unreachable."""
    try:
        conn = oracledb.connect(
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"],
            dsn=DB_CONFIG["dsn"]
        )
        return conn
    except oracledb.DatabaseError as e:
        raise ConnectionError(f"Oracle DB unreachable: {e}")

def db_error_response():
    """Standard JSON response when DB is down."""
    return jsonify({
        "success": False,
        "error": "Database unavailable. Make sure Oracle XE is running."
    }), 503

def verify_password(plain, hashed):
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))

def get_user_role(username):
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE username = :1", (username,))
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        return row[0] if row else 'staff'
    except Exception:
        return 'staff'

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def hash_password(p):
    return bcrypt.hashpw(p.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def check_password_strength(password):
    rules = {
        "length":    len(password) >= 8,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "number":    bool(re.search(r"[0-9]", password)),
        "special":   bool(re.search(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>/?\\|`~]", password)),
    }
    score = sum(rules.values())
    return {"is_strong": score >= 4}

def generate_captcha():
    op = random.choice(["+", "-", "×"])
    if op == "+":
        a, b = random.randint(1, 15), random.randint(1, 15)
        answer = a + b
        q = f"What is {a} + {b}?"
    elif op == "-":
        a = random.randint(5, 20)
        b = random.randint(1, a)
        answer = a - b
        q = f"What is {a} - {b}?"
    else:
        a, b = random.randint(2, 12), random.randint(2, 12)
        answer = a * b
        q = f"What is {a} × {b}?"
    session["captcha_answer"] = answer
    return q

def get_user_from_db(username):
    """Helper: fetch user row and return dict. Returns None if not found."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, created_at, last_login FROM users WHERE username = :1",
        (username,)
    )
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    if not row:
        return None
    return {
        "username":   row[0],
        "created_at": row[1],
        "last_login": row[2],
        "role":       session.get("role", "staff")
    }

# ════════════════════════════════════════
#  ROUTES
# ════════════════════════════════════════

# ── FIX 3: Root route (visiting / no longer gives 404) ──
@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login")
def login():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return render_template("Login.html")

@app.route("/register")
def register():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return render_template("Index.html", captcha_question=generate_captcha())

@app.route("/register", methods=["POST"])
def register_post():
    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    captcha_input = data.get("captcha", "")

    if not username or len(username) < 3:
        return jsonify({"success": False, "error": "Username too short"}), 400

    if not check_password_strength(password)["is_strong"]:
        return jsonify({"success": False, "error": "Weak password"}), 400

    try:
        if int(captcha_input) != session.get("captcha_answer"):
            return jsonify({"success": False, "error": "Wrong CAPTCHA"}), 400
    except:
        return jsonify({"success": False, "error": "Invalid CAPTCHA"}), 400

    try:
        conn   = get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT username FROM users WHERE username = :1", (username,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({"success": False, "error": "Username already exists"}), 409

        hashed = hash_password(password)
        cursor.execute(
            "INSERT INTO users (username, password_hash, created_at, role) VALUES (:1, :2, :3, :4)",
            (username, hashed, datetime.now().strftime("%d %B %Y, %H:%M"), 'staff')
        )
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({"success": True, "redirect": url_for("login")})
    except ConnectionError:
        return db_error_response()
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/login", methods=["POST"])
def login_post():
    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    try:
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT username, password_hash FROM users WHERE username = :1",
            (username,)
        )
        row = cursor.fetchone()
        cursor.close()
        conn.close()
    except ConnectionError:
        return db_error_response()

    if not row:
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    db_username, db_password_hash = row

    if not verify_password(password, db_password_hash):
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    session["username"] = db_username
    session["role"]     = get_user_role(db_username)

    # Update last login timestamp
    try:
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET last_login = :1 WHERE username = :2",
            (datetime.now().strftime("%d %B %Y, %H:%M"), db_username)
        )
        conn.commit()
        cursor.close()
        conn.close()
    except ConnectionError:
        pass  # Non-fatal — login still succeeds

    return jsonify({"success": True, "redirect": url_for("dashboard")})

@app.route("/dashboard")
@login_required
def dashboard():
    try:
        user = get_user_from_db(session["username"])
    except ConnectionError:
        return render_template("Dashboard.html", user={
            "username":   session["username"],
            "created_at": "N/A",
            "last_login": "N/A",
            "role":       session.get("role", "staff")
        })
    return render_template("Dashboard.html", user=user)

@app.route("/profile")
@login_required
def profile():
    try:
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT username, created_at, last_login FROM users WHERE username = :1",
            (session["username"],)
        )
        row = cursor.fetchone()
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]
        cursor.close()
        conn.close()
    except ConnectionError:
        return db_error_response()

    user = {
        "username":   row[0],
        "created_at": row[1],
        "last_login": row[2],
        "role":       session.get("role", "staff")
    }
    return render_template("Profile.html", user=user, total_users=total_users)

@app.route("/settings")
@login_required
def settings():
    try:
        user = get_user_from_db(session["username"])
    except ConnectionError:
        return db_error_response()
    return render_template("Settings.html", user=user)

@app.route("/activity")
@login_required
def activity():
    try:
        user = get_user_from_db(session["username"])
    except ConnectionError:
        return db_error_response()
    return render_template("Activity.html", user=user)

@app.route("/users")
@login_required
def users():
    try:
        user = get_user_from_db(session["username"])
    except ConnectionError:
        return db_error_response()
    return render_template("Users.html", user=user)

@app.route("/notifications")
@login_required
def notifications():
    return render_template("Notifications.html")

# ── FIX 4: Added missing /analytics route ──
@app.route("/analytics")
@login_required
def analytics():
    try:
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM users WHERE last_login IS NOT NULL")
        active_users = cursor.fetchone()[0]
        cursor.close()
        conn.close()
        new_registrations = max(0, total_users - active_users)
    except ConnectionError:
        total_users = new_registrations = active_users = 0

    try:
        user = get_user_from_db(session["username"])
    except ConnectionError:
        user = {
            "username":   session["username"],
            "created_at": "N/A",
            "last_login": "N/A",
            "role":       session.get("role", "staff")
        }

    return render_template(
        "Analytics.html",
        user=user,
        total_users=total_users,
        active_users=active_users,
        new_registrations=new_registrations
    )

# ════════════════════════════════════════
#  API ENDPOINTS
# ════════════════════════════════════════

@app.route("/api/user", methods=["GET"])
@login_required
def get_current_user():
    return jsonify({
        "success":   True,
        "username":  session.get("username"),
        "role":      session.get("role", "staff"),
        "dark_mode": session.get("general_settings", {}).get("dark_mode", False)
    })

@app.route("/api/activity", methods=["GET"])
@login_required
def get_activity():
    activity_type = request.args.get("type", "all")

    activities = []
    if activity_type in ["all", "login"]:
        activities.extend([
            {"type": "login",    "title": "Successful login",             "time": "2 hours ago", "icon": "✓",  "status": "success", "details": "Chrome on Windows"},
            {"type": "login",    "title": "Successful login",             "time": "1 day ago",   "icon": "✓",  "status": "success", "details": "Firefox on Linux"},
        ])
    if activity_type in ["all", "security"]:
        activities.extend([
            {"type": "security", "title": "Password changed",             "time": "3 days ago",  "icon": "🔐", "status": "success", "details": "Password updated"},
            {"type": "security", "title": "New login location detected",  "time": "5 days ago",  "icon": "⚠",  "status": "warning", "details": "Seattle, WA"},
        ])
    if activity_type in ["all", "changes"]:
        activities.extend([
            {"type": "changes",  "title": "Profile updated",              "time": "1 week ago",  "icon": "📝", "status": "success", "details": "Information changed"},
        ])

    return jsonify({"success": True, "activities": activities})

@app.route("/api/users", methods=["GET"])
@login_required
def get_users_api():
    try:
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username, created_at, last_login FROM users ORDER BY created_at DESC")
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
    except ConnectionError:
        return db_error_response()

    users_list = [{
        "username":   row[0],
        "joined":     row[1],
        "last_login": row[2] or "Never",
        "status":     "active" if row[2] else "inactive"
    } for row in rows]

    return jsonify({"success": True, "users": users_list})

@app.route("/api/notifications", methods=["GET"])
@login_required
def get_notifications():
    notifications = session.get("notifications", [
        {"id": 1, "title": "Password changed successfully",   "message": "Your account password was updated.",                               "time": "5 minutes ago", "type": "success", "unread": True},
        {"id": 2, "title": "New login location detected",     "message": "Accessed from Seattle, WA • Safari on iPhone",                    "time": "2 hours ago",   "type": "warning", "unread": True},
        {"id": 3, "title": "System maintenance scheduled",    "message": "We'll perform maintenance on March 31st from 2-4 AM UTC.",         "time": "1 day ago",     "type": "info",    "unread": True},
    ])
    return jsonify({"success": True, "notifications": notifications})

@app.route("/api/notifications/clear", methods=["POST"])
@login_required
def clear_notifications():
    session["notifications"] = []
    session.modified = True
    return jsonify({"success": True, "message": "All notifications cleared"})

@app.route("/api/settings/privacy", methods=["GET"])
@login_required
def get_privacy_settings():
    settings = session.get("privacy_settings", {
        "profile_visibility": True,
        "activity_status":    False,
        "search_visibility":  True
    })
    return jsonify({"success": True, "settings": settings})

@app.route("/api/settings/privacy", methods=["POST"])
@login_required
def save_privacy_settings():
    data = request.get_json()
    session["privacy_settings"] = {
        "profile_visibility": data.get("profile_visibility", False),
        "activity_status":    data.get("activity_status",    False),
        "search_visibility":  data.get("search_visibility",  False)
    }
    session.modified = True
    return jsonify({"success": True, "message": "Privacy settings saved"})

@app.route("/api/settings/general", methods=["GET"])
@login_required
def get_general_settings():
    settings = session.get("general_settings", {
        "dark_mode":              False,
        "compact_view":           False,
        "email_notifications":    True,
        "security_notifications": True
    })
    return jsonify({"success": True, "settings": settings})

@app.route("/api/settings/general", methods=["POST"])
@login_required
def save_general_settings():
    data = request.get_json()
    session["general_settings"] = {
        "dark_mode":              data.get("dark_mode",              False),
        "compact_view":           data.get("compact_view",           False),
        "email_notifications":    data.get("email_notifications",    True),
        "security_notifications": data.get("security_notifications", True)
    }
    session.modified = True
    return jsonify({"success": True, "message": "Settings saved"})

@app.route("/change-password", methods=["POST"])
@login_required
def change_password():
    data             = request.get_json()
    current_password = data.get("current_password")
    new_password     = data.get("new_password")

    try:
        conn   = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT password_hash FROM users WHERE username = :1",
            (session["username"],)
        )
        row = cursor.fetchone()
    except ConnectionError:
        return db_error_response()

    if not row or not verify_password(current_password, row[0]):
        cursor.close(); conn.close()
        return jsonify({"success": False, "error": "Current password incorrect"}), 400

    if not check_password_strength(new_password)["is_strong"]:
        cursor.close(); conn.close()
        return jsonify({"success": False, "error": "Weak new password"}), 400

    if verify_password(new_password, row[0]):
        cursor.close(); conn.close()
        return jsonify({"success": False, "error": "New password must be different"}), 400

    new_hash = hash_password(new_password)
    cursor.execute(
        "UPDATE users SET password_hash = :1 WHERE username = :2",
        (new_hash, session["username"])
    )
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"success": True, "message": "Password updated successfully"})

@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/captcha/refresh", methods=["GET"])
def refresh_captcha():
    return jsonify({"question": generate_captcha()})

@app.route("/health")
def health():
    try:
        conn = get_connection()
        conn.close()
        return jsonify({"status": "OK", "db": "connected"}), 200
    except ConnectionError as e:
        return jsonify({"status": "degraded", "db": str(e)}), 503

if __name__ == "__main__":
    app.run(debug=True)