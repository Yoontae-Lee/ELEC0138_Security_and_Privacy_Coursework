import csv
import os
import sys
import time
from collections import defaultdict, deque
sys.path.insert(0, os.path.dirname(__file__))
from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from banking_system import AUDIT_LOG_FILE, DEFENSE_MFA_ENABLED, DEFENSE_RATE_LIMIT_ENABLED, BankingSystem
import os

DEFENSE_DATA_MIN_ENABLED     = os.environ.get("DEFENSE_DATA_MIN",     "true").lower() == "true"
DEFENSE_SESSION_AUTH_ENABLED = os.environ.get("DEFENSE_SESSION_AUTH", "true").lower() == "true"
from mfa_mailer import DEFAULT_MFA_DESTINATION, normalize_mfa_destination, send_mfa_code

app = Flask(__name__)
app.secret_key = "testbed-secret-key-not-for-production"
bank = BankingSystem()

_flood_log: deque[float] = deque()
_request_buckets: dict[tuple[str, str], deque[float]] = defaultdict(deque)
_RATE_LIMIT_RULES = (
    ("auth", {"/login", "/api/login", "/api/login/verify"}, 6, 60),
    ("api", None, 45, 60),
    ("default", None, 120, 60),
)
_RATE_LIMIT_EXEMPT_PATHS = {"/api/sessions", "/api/account"}

def seed() -> None:
    if not bank._usernames:
        bank.create_account(
            "alice",
            "alice_pass_123",
            5000.00,
            {
                "name": "Alice Kim",
                "email": "alice@example.com",
                "phone": "+44-7700-000001",
                "trusted_devices": ["BROWSER-HOME-001"],
            },
        )
        bank.create_account(
            "bob",
            "bob_pass_456",
            1000.00,
            {
                "name": "Bob Lee",
                "email": "bob@example.com",
                "phone": "+44-7700-000002",
                "trusted_devices": ["BROWSER-HOME-001"],
            },
        )
seed()

def get_session_obj():
    sid = session.get("session_id")
    if not sid:
        return None
    stored = bank._sessions.get(sid)
    if stored is None or not stored.authenticated or stored.revoked:
        return None
    return stored

def get_pending_login():
    challenge_id = session.get("pending_login_id")
    if not challenge_id:
        return None
    challenge = bank.get_pending_login(challenge_id)
    if challenge is None:
        session.pop("pending_login_id", None)
    return challenge

def clear_pending_login() -> None:
    challenge_id = session.pop("pending_login_id", None)
    if challenge_id:
        bank.discard_pending_login(challenge_id)
    session.pop("mfa_delivery_error", None)
    session.pop("mfa_fallback_code", None)
    session.pop("delivery_target", None)

def client_ip() -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"

def rate_limit_rule(path: str) -> tuple[str, int, int]:
    for name, paths, limit, window in _RATE_LIMIT_RULES:
        if name == "auth" and path in paths:
            return name, limit, window
        if name == "api" and path.startswith("/api/"):
            return name, limit, window
    return "default", 120, 60

def audit_context() -> tuple[str, str, str, str]:
    sess = get_session_obj()
    if sess is not None:
        return sess.user_id, sess.account_id, sess.device_id, sess.location
    challenge = get_pending_login()
    if challenge is not None:
        return (
            challenge.user_id,
            challenge.account_id,
            challenge.device_id,
            challenge.location,
        )
    user_id = (request.form.get("username") or "ANON").strip() or "ANON"
    device_id = (
        request.headers.get("X-Device-Id")
        or request.form.get("device_id")
        or "WEB-CLIENT"
    )
    location = (
        request.headers.get("X-Location")
        or request.form.get("location")
        or "Unknown"
    )
    return user_id, "", device_id, location

def login_context(error: str | None = None):
    pending_login = get_pending_login()
    delivery_target = session.get("delivery_target", DEFAULT_MFA_DESTINATION)
    if pending_login is not None:
        account = bank._accounts.get(pending_login.account_id)
        if account is not None:
            delivery_target = normalize_mfa_destination(
                account.personal_data.get("phone")
            )
    return {
        "error": error,
        "pending_login": pending_login,
        "delivery_target": delivery_target,
        "mfa_delivery_error": session.get("mfa_delivery_error"),
        "mfa_fallback_code": session.get("mfa_fallback_code"),
        "username": request.form.get("username", ""),
        "device_id": request.form.get("device_id", "BROWSER-HOME-001"),
        "location": request.form.get("location", "London, UK"),
    }

def mask_email(value: str) -> str:
    if not value or "@" not in value:
        return "REDACTED"
    local, domain = value.split("@", 1)
    if len(local) <= 2:
        local_masked = local[0] + "*" * max(len(local) - 1, 1)
    else:
        local_masked = local[:2] + "*" * max(len(local) - 2, 2)
    return f"{local_masked}@{domain}"

def mask_phone(value: str) -> str:
    if not value:
        return "REDACTED"
    digits = [c for c in value if c.isdigit()]
    if len(digits) < 4:
        return "REDACTED"
    last4 = ''.join(digits[-4:])
    return f"***-***-{last4}"

def minimise_account_view(account: dict) -> dict:
    personal = dict(account.get("personal_data") or {})
    minimal_personal = {
        "name": personal.get("name", ""),
        "email": mask_email(str(personal.get("email", ""))),
        "phone": mask_phone(str(personal.get("phone", ""))),
        "location": "REDACTED",
    }
    return {
        "account_id": account.get("account_id"),
        "owner": account.get("owner"),
        "balance": account.get("balance"),
        "personal_data": minimal_personal,
        "data_minimised": True,
    }

@app.before_request
def count_requests():
    now = time.time()
    _flood_log.append(now)
    while _flood_log and _flood_log[0] <= now - 60:
        _flood_log.popleft()
    rule_name, limit, window = rate_limit_rule(request.path)
    bucket = _request_buckets[(client_ip(), rule_name)]
    while bucket and bucket[0] <= now - window:
        bucket.popleft()

    # Simulate heavy processing when defense is OFF 
    # Real bank servers perform encryption, DB queries, and
    # session management per request. Flask dev server is too
    # lightweight, so we simulate that cost for flood requests.
    if not DEFENSE_RATE_LIMIT_ENABLED:
        try:
            json_body = request.get_json(silent=True, force=False) or {}
        except Exception:
            json_body = {}
        device_id = (
            request.headers.get("X-Device-Id", "")
            or json_body.get("device_id", "")
            or request.form.get("device_id", "")
        )
        if device_id.startswith("FLOOD-"):
            _ = [i ** 2 for i in range(50000)]

    if request.path not in _RATE_LIMIT_EXEMPT_PATHS:
        if DEFENSE_RATE_LIMIT_ENABLED and len(bucket) >= limit:
            user_id, account_id, device_id, location = audit_context()
            bank._audit(
                "RATE_LIMITED",
                user_id,
                account_id,
                device_id,
                location,
                success=False,
                details=f"path={request.path};limit={limit}/{window}s;ip={client_ip()}",
            )
            if request.path.startswith("/api/"):
                return (
                    jsonify(
                        {"ok": False, "error": "Too many requests. Please slow down."}
                    ),
                    429,
                )
            if request.path == "/login":
                return render_template("login.html", **login_context(error="Too many requests. Please wait a moment and try again.")), 429
            return "Too many requests. Please wait a moment and try again.", 429

        bucket.append(now)

@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.args.get("reset") == "1":
        clear_pending_login()
        return redirect(url_for("login"))
    error = None
    if request.method == "POST":
        phase = request.form.get("phase", "credentials")
        if phase == "mfa":
            challenge_id = session.get("pending_login_id", "")
            otp_code = request.form.get("otp_code", "").strip()
            result = bank.complete_login(challenge_id, otp_code)
            if result.get("ok"):
                session.pop("pending_login_id", None)
                session.pop("mfa_delivery_error", None)
                session.pop("mfa_fallback_code", None)
                session["session_id"] = result["session"].session_id
                return redirect(url_for("dashboard"))
            error = result["error"]
        else:
            clear_pending_login()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            device_id = request.headers.get(
                "X-Device-Id", request.form.get("device_id", "BROWSER-HOME-001")
            )
            location = request.headers.get(
                "X-Location", request.form.get("location", "London, UK")
            )
            result = bank.start_login(username, password, device_id, location)
            if result.get("ok"):
                # DEFENSE_MFA=false → session_id returned directly
                if "session_id" in result:
                    session["session_id"] = result["session_id"]
                    return redirect(url_for("dashboard"))
                # DEFENSE_MFA=true → MFA challenge
                session["pending_login_id"] = result["challenge_id"]
                delivery_target = normalize_mfa_destination(
                    result.get("delivery_target")
                )
                session["delivery_target"] = delivery_target
                delivered, detail = send_mfa_code(
                    result["demo_code"],
                    username,
                    device_id,
                    location,
                    delivery_target,
                )
                if delivered:
                    session.pop("mfa_delivery_error", None)
                    session.pop("mfa_fallback_code", None)
                    bank._audit(
                        "LOGIN_MFA_DELIVERED",
                        username,
                        result["account_id"],
                        device_id,
                        location,
                        success=True,
                        details=f"destination={delivery_target};{detail}",
                    )
                else:
                    session.pop("mfa_delivery_error", None)
                    session["mfa_fallback_code"] = result["demo_code"]
                    bank._audit(
                        "LOGIN_MFA_DELIVERY_FAILED",
                        username,
                        result["account_id"],
                        device_id,
                        location,
                        success=False,
                        details=f"destination={delivery_target};{detail}",
                    )
            else:
                error = result["error"]
    return render_template("login.html", **login_context(error=error))

@app.route("/dashboard")
def dashboard():
    sess = get_session_obj()
    if not sess:
        return redirect(url_for("login"))
    account = bank.view_account(sess)
    benes = bank.get_beneficiaries(sess)
    history = bank.get_transaction_history(sess, limit=10)
    return render_template(
        "dashboard.html",
        account=account,
        benes=benes,
        history=history,
        session=sess,
    )

@app.route("/beneficiary/add", methods=["POST"])
def add_beneficiary():
    sess = get_session_obj()
    if not sess:
        return redirect(url_for("login"))
    target = request.form.get("target_account", "").strip()
    nickname = request.form.get("nickname", "").strip()
    if target and nickname:
        bank.add_beneficiary(sess, target, nickname)
    return redirect(url_for("dashboard"))

@app.route("/transfer", methods=["POST"])
def transfer():
    sess = get_session_obj()
    if not sess:
        return redirect(url_for("login"))
    bene_id = request.form.get("beneficiary_id", "").strip()
    try:
        amount = float(request.form.get("amount", 0))
    except ValueError:
        amount = 0
    if bene_id and amount > 0:
        bank.transfer(sess, bene_id, amount)
    return redirect(url_for("dashboard"))

@app.route("/logout")
def logout():
    sid = session.get("session_id")
    if sid:
        bank.invalidate_session(sid)
    clear_pending_login()
    session.clear()
    return redirect(url_for("login"))

@app.route("/audit")
def audit():
    rows = []
    if AUDIT_LOG_FILE.exists():
        with open(AUDIT_LOG_FILE, newline="") as f:
            rows = list(csv.DictReader(f))
    rows.reverse()
    return render_template("audit.html", rows=rows)

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.json or {}
    device_id = request.headers.get("X-Device-Id", data.get("device_id", "API-CLIENT"))
    location = request.headers.get("X-Location", data.get("location", "Unknown"))
    username = data.get("username", "")
    result = bank.start_login(username, data.get("password", ""), device_id, location)
    if result.get("ok"):
        # DEFENSE_MFA=false → session_id returned directly
        if "session_id" in result:
            return jsonify({"ok": True, "session_id": result["session_id"]})

        # DEFENSE_MFA=true → MFA challenge
        delivery_target = normalize_mfa_destination(result.get("delivery_target"))
        delivered, detail = send_mfa_code(
            result["demo_code"],
            username,
            device_id,
            location,
            delivery_target,
        )
        if delivered:
            bank._audit(
                "LOGIN_MFA_DELIVERED",
                username,
                result["account_id"],
                device_id,
                location,
                success=True,
                details=f"destination={delivery_target};{detail}",
            )
        else:
            bank._audit(
                "LOGIN_MFA_DELIVERY_FAILED",
                username,
                result["account_id"],
                device_id,
                location,
                success=False,
                details=f"destination={delivery_target};{detail}",
            )
        return jsonify(
            {
                "ok": False,
                "requires_mfa": True,
                "challenge_id": result["challenge_id"],
                "is_new_device": result["is_new_device"],
                "delivery_target": delivery_target,
                "delivery_ok": delivered,
                "fallback_code": None if delivered else result["demo_code"],
                "error": "MFA required",
            }
        )
    locked_error = (
        "Too many failed attempts" in result["error"]
        or "Account locked after repeated failures" in result["error"]
    )
    status = 423 if locked_error else 401
    return jsonify({"ok": False, "error": result["error"]}), status

@app.route("/api/login/verify", methods=["POST"])
def api_login_verify():
    data = request.json or {}
    result = bank.complete_login(data.get("challenge_id", ""), data.get("otp_code", ""))
    if result.get("ok"):
        return jsonify({"ok": True, "session_id": result["session"].session_id})
    return jsonify({"ok": False, "error": result["error"]}), 401

@app.route("/api/beneficiary/add", methods=["POST"])
def api_add_beneficiary():
    data = request.json or {}
    sess_id = data.get("session_id")
    sess = bank._sessions.get(sess_id)
    if not sess_id or sess is None or not sess.authenticated or sess.revoked:
        return jsonify({"ok": False, "error": "Invalid session"}), 403
    bene = bank.add_beneficiary(sess, data.get("target_account", ""), data.get("nickname", ""))
    if bene:
        return jsonify({"ok": True, "beneficiary_id": bene.beneficiary_id})
    return jsonify({"ok": False}), 400

@app.route("/api/transfer", methods=["POST"])
def api_transfer():
    data = request.json or {}
    sess_id = data.get("session_id")
    sess = bank._sessions.get(sess_id)
    if not sess_id or sess is None or not sess.authenticated or sess.revoked:
        return jsonify({"ok": False, "error": "Invalid session"}), 403
    txn = bank.transfer(sess, data.get("beneficiary_id", ""), float(data.get("amount", 0)))
    if txn:
        return jsonify({"ok": True, "status": txn.status, "txn_id": txn.transaction_id})
    return jsonify({"ok": False}), 400

@app.route("/api/sessions", methods=["GET"])
def api_sessions():
    # Defense: require authentication
    if DEFENSE_SESSION_AUTH_ENABLED:
        sess = get_session_obj()
        if not sess:
            return jsonify({"ok": False, "error": "Unauthorized"}), 403
    active = [
        {
            "session_id": s.session_id,
            "user_id": s.user_id,
            "account_id": s.account_id,
            "device_id": s.device_id,
            "location": s.location,
            "login_time": s.login_time,
            "mfa_verified": s.mfa_verified,
        }
        for s in bank._sessions.values()
        if s.authenticated and not s.revoked
    ]
    return jsonify({"ok": True, "sessions": active})

@app.route("/api/account", methods=["POST"])
def api_account():
    data = request.json or {}
    sess_id = data.get("session_id", "")
    sess = bank._sessions.get(sess_id)
    if not sess_id or sess is None or not sess.authenticated or sess.revoked:
        return jsonify({"ok": False, "error": "Invalid session"}), 403

    account = bank.view_account(sess)
    if account is None:
        return jsonify({"ok": False, "error": "Account unavailable"}), 404

    returned_account = minimise_account_view(account) if DEFENSE_DATA_MIN_ENABLED else account
    bank._audit(
        "ACCOUNT_DATA_EXPOSED",
        sess.user_id,
        sess.account_id,
        sess.device_id,
        sess.location,
        success=True,
        details=(
            f"api=/api/account;data_minimised={str(DEFENSE_DATA_MIN_ENABLED).lower()};"
            f"source_ip={client_ip()}"
        ),
    )
    return jsonify({"ok": True, "account": returned_account})

@app.route("/api/flood/stats", methods=["GET"])
def flood_stats():
    now = time.time()
    last_1s = sum(1 for t in _flood_log if t > now - 1)
    last_10s = sum(1 for t in _flood_log if t > now - 10)
    return jsonify(
        {
            "requests_last_1s": last_1s,
            "requests_last_10s": last_10s,
            "total_in_window": len(_flood_log),
        }
    )

if __name__ == "__main__":
    print("\n  Banking Testbed running at http://localhost:5000\n")
    print("  Threats available:")
    print("    Threat 1 - Account Takeover   : python account_takeover.py")
    print("    Threat 2 - HTTP Flood         : python http_dos.py")
    print("    Threat 3 - Data Exfiltration  : python data_exfiltration.py\n")
    debug_mode = os.environ.get("BANKING_DEBUG", "0") == "1"
    threaded   = DEFENSE_RATE_LIMIT_ENABLED
    app.run(host="0.0.0.0", debug=debug_mode, port=5000, threaded=threaded)