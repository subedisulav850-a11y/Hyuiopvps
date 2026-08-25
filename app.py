"""Sulav VPS hosting control panel.

The dashboard remains Flask-compatible for the existing templates, while the
exported ``app`` is a FastAPI ASGI application so it works on Vercel and with
Uvicorn.  Project dependencies are installed into isolated virtual environments
rather than the host interpreter.
"""
import hashlib
import hmac
import ipaddress
import io
import json
import os
import re
import secrets
import shlex
import socket
import shutil
import signal
import subprocess
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

import psutil
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from asgiref.wsgi import WsgiToAsgi
from flask import (
    Flask, abort, jsonify, redirect, render_template, request, Response,
    send_file, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


BASE_DIR = Path(__file__).resolve().parent
IS_VERCEL = bool(os.environ.get("VERCEL"))
APP_ENV = os.environ.get("APP_ENV", "production" if IS_VERCEL else "development").lower()
SECRET_KEY = os.environ.get("SECRET_KEY", "")
if not SECRET_KEY:
    # Do not abort module import when a deployment was created before its
    # environment variables were configured.  Vercel imports the module
    # before it can serve even /healthz, so raising here turns a configuration
    # mistake into an opaque 500 for every route.  The generated key is only
    # an emergency per-process fallback; sessions are invalidated on restart.
    SECRET_KEY = secrets.token_urlsafe(48)
    if APP_ENV == "production":
        print(
            "WARNING: SECRET_KEY is not configured; using an ephemeral key. "
            "Set SECRET_KEY in the deployment environment.",
            file=sys.stderr,
        )

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Sulav")
CF_SITE_KEY = os.environ.get("CF_TURNSTILE_SITE_KEY", "").strip()
CF_SECRET_KEY = os.environ.get("CF_TURNSTILE_SECRET_KEY", "").strip()
ADMIN_PATH = re.sub(r"[^A-Za-z0-9_-]", "", os.environ.get("ADMIN_PATH", "admin"))[:64] or "admin"
SITE_NAME = os.environ.get("SITE_NAME", "Sulav VPS")[:80]
ALLOW_CONSOLE = os.environ.get("ENABLE_SERVER_CONSOLE", "false" if IS_VERCEL else "true").lower() in {"1", "true", "yes"}
TRUSTED_HOSTS = {h.strip().lower() for h in os.environ.get("TRUSTED_HOSTS", "").split(",") if h.strip()}
TRUST_PROXY_HEADERS = os.environ.get("TRUST_PROXY_HEADERS", "true" if IS_VERCEL else "false").lower() in {"1", "true", "yes"}
TRUSTED_PROXY_IPS = {h.strip() for h in os.environ.get("TRUSTED_PROXY_IPS", "127.0.0.1,::1").split(",") if h.strip()}
def env_int(name, default, minimum=None, maximum=None):
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        value = default
    if minimum is not None:
        value = max(minimum, value)
    if maximum is not None:
        value = min(maximum, value)
    return value


MAX_UPLOAD_BYTES = env_int("MAX_UPLOAD_MB", 64, 1, 1024) * 1024 * 1024
MAX_ZIP_FILES = env_int("MAX_ZIP_FILES", 1000, 1, 100000)
MAX_ZIP_UNCOMPRESSED_BYTES = env_int("MAX_ZIP_UNCOMPRESSED_MB", 256, 1, 4096) * 1024 * 1024
SECURITY_EVENT_LIMIT = env_int("SECURITY_EVENT_LIMIT", 2000, 100, 10000)

RUNTIME_DIR = Path(
    os.environ.get("RUNTIME_DIR", "/tmp/sulav-vps" if IS_VERCEL else str(BASE_DIR))
).resolve()
DATA_FILE = RUNTIME_DIR / "data.json"
SERVERS_DIR = RUNTIME_DIR / "servers"
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
SERVERS_DIR.mkdir(parents=True, exist_ok=True)
if IS_VERCEL and not DATA_FILE.exists():
    source_data = BASE_DIR / "data.json"
    if source_data.exists():
        try:
            DATA_FILE.write_text(source_data.read_text())
        except OSError:
            pass

flask_app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))
flask_app.secret_key = SECRET_KEY
flask_app.config.update(
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_VERCEL or os.environ.get("COOKIE_SECURE", "0").lower() in {"1", "true", "yes"},
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)

RUNNING_PROCESSES = {}
AUTO_RESTART_TIMERS = {}
RATE_BUCKETS = {}
RATE_LOCK = threading.Lock()


def normalize_ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return "unknown"


def get_client_ip(req):
    """Read a real client IP only when the immediate peer is trusted."""
    remote = normalize_ip(req.remote_addr or "unknown")
    if not TRUST_PROXY_HEADERS or (remote not in TRUSTED_PROXY_IPS and not IS_VERCEL):
        return remote
    for candidate in [req.headers.get("CF-Connecting-IP"), req.headers.get("X-Real-IP")]:
        normalized = normalize_ip(candidate) if candidate else "unknown"
        if normalized != "unknown":
            return normalized
    forwarded = req.headers.get("X-Forwarded-For", "")
    for candidate in forwarded.split(","):
        normalized = normalize_ip(candidate)
        if normalized != "unknown":
            return normalized
    return remote


def security_state(data):
    security = data.setdefault("security", {})
    security.setdefault("banned_ips", {})
    security.setdefault("ip_events", [])
    return security


def is_ip_banned(ip):
    if ip == "unknown":
        return False
    data = load_data()
    security = security_state(data)
    entry = security["banned_ips"].get(ip)
    if not entry:
        return False
    expires = entry.get("expires_at")
    if expires:
        try:
            if datetime.fromisoformat(expires) <= datetime.now():
                security["banned_ips"].pop(ip, None)
                save_data(data)
                return False
        except ValueError:
            pass
    return True


def record_ip_event(ip, req):
    if ip == "unknown" or req.path == "/healthz":
        return
    data = load_data()
    security = security_state(data)
    events = security["ip_events"]
    now = datetime.now()
    path = req.path[:200]
    if events and events[-1].get("ip") == ip and events[-1].get("path") == path:
        try:
            if now - datetime.fromisoformat(events[-1]["timestamp"]) < timedelta(seconds=10):
                return
        except ValueError:
            pass
    events.append({
        "ip": ip, "timestamp": now.isoformat(timespec="seconds"),
        "method": req.method, "path": path,
        "user_agent": req.headers.get("User-Agent", "")[:180],
    })
    security["ip_events"] = events[-SECURITY_EVENT_LIMIT:]
    save_data(data)


def security_snapshot(data):
    security = security_state(data)
    banned = []
    for ip, entry in security["banned_ips"].items():
        banned.append({"ip": ip, **entry})
    banned.sort(key=lambda item: item.get("created_at", ""), reverse=True)
    return {"banned_ips": banned, "recent_events": list(reversed(security["ip_events"][-100:]))}


# ─── Data helpers ─────────────────────────────────────────────────────────────

def load_data():
    if DATA_FILE.exists():
        try:
            return json.loads(DATA_FILE.read_text())
        except Exception:
            pass
    return {
        "servers": {}, "users": {},
        "settings": {
            "maintenance": False,
            "maintenance_msg": "System under maintenance.",
            "accent_color": "#00ff41",
            "broadcast": {"active": False, "message": "", "btype": "info"}
        }
    }

def save_data(data):
    # Atomic replacement prevents a concurrent request from leaving truncated JSON.
    tmp = DATA_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    tmp.replace(DATA_FILE)


def hash_password(password):
    return generate_password_hash(password, method="scrypt")


def password_matches(stored, password):
    if not stored:
        return False
    if stored.startswith(("scrypt:", "pbkdf2:", "argon2:")):
        try:
            return check_password_hash(stored, password)
        except ValueError:
            return False
    # Upgrade the old archive's SHA-256 records after a successful login.
    return hmac.compare_digest(stored, hashlib.sha256(password.encode()).hexdigest())


def safe_path(base, relative):
    """Resolve a user-supplied path and reject traversal outside ``base``."""
    relative = str(relative or "").replace("\\", "/")
    candidate = (base / relative).resolve()
    base_resolved = base.resolve()
    if candidate != base_resolved and base_resolved not in candidate.parents:
        raise ValueError("Path escapes project directory")
    return candidate


def project_dir(name):
    return safe_path(SERVERS_DIR, name)


def ensure_project_venv(name):
    venv_dir = project_dir(name) / "venv"
    python_bin = venv_dir / "bin" / "python"
    if not python_bin.exists():
        venv_dir.parent.mkdir(parents=True, exist_ok=True)
        result = subprocess.run(
            [sys.executable, "-m", "venv", str(venv_dir)],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0 or not python_bin.exists():
            raise RuntimeError((result.stderr or result.stdout or "Could not create virtual environment")[-500:])
    return python_bin


def pip_command(name):
    python_bin = ensure_project_venv(name)
    return [str(python_bin), "-m", "pip"]


def runtime_environment(name):
    env = os.environ.copy()
    venv_bin = str(project_dir(name) / "venv" / "bin")
    env["PATH"] = venv_bin + os.pathsep + env.get("PATH", "")
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONNOUSERSITE"] = "1"
    return env


# ─── Context processor — inject theme/broadcast into every template ───────────

@flask_app.context_processor
def inject_globals():
    data = load_data()
    s = data.get("settings", {})
    session.setdefault("csrf_token", secrets.token_urlsafe(32))
    return {
        "site_name":    SITE_NAME,
        "theme_color":  s.get("accent_color", "#00ff41"),
        "broadcast":    s.get("broadcast", {}),
        "admin_path":   ADMIN_PATH,
        "cf_site_key":  CF_SITE_KEY,
        "csrf_token":   session["csrf_token"],
        "console_enabled": ALLOW_CONSOLE,
        "request_root": request.url_root.rstrip("/"),
        "client_ip": request.environ.get("client_ip", get_client_ip(request)),
    }


@flask_app.before_request
def security_gate():
    host = request.host.split(":", 1)[0].lower()
    if TRUSTED_HOSTS and host not in TRUSTED_HOSTS and host not in {"localhost", "127.0.0.1"}:
        abort(400)
    session.setdefault("csrf_token", secrets.token_urlsafe(32))
    client_ip = get_client_ip(request)
    request.environ["client_ip"] = client_ip
    if is_ip_banned(client_ip):
        return jsonify({"success": False, "error": "Your IP address is blocked"}), 403
    record_ip_event(client_ip, request)
    view_args = request.view_args or {}
    server_name = view_args.get("name")
    if server_name:
        current = load_data().get("servers", {}).get(server_name)
        if current and current.get("owner") != session.get("username") and not session.get("admin"):
            return jsonify({"success": False, "error": "Access denied"}), 403
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        token = request.headers.get("X-CSRF-Token", "")
        if not token and request.form:
            token = request.form.get("csrf_token", "")
        if not hmac.compare_digest(token, session.get("csrf_token", "")):
            return jsonify({"success": False, "error": "CSRF validation failed"}), 403
    if request.path.endswith("/login") and request.method == "POST":
        now = datetime.now().timestamp()
        key = f"login:{request.remote_addr or 'unknown'}"
        with RATE_LOCK:
            attempts = [t for t in RATE_BUCKETS.get(key, []) if now - t < 300]
            if len(attempts) >= 10:
                return jsonify({"success": False, "error": "Too many attempts. Try again later."}), 429
            attempts.append(now)
            RATE_BUCKETS[key] = attempts


@flask_app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com https://challenges.cloudflare.com; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; frame-src https://challenges.cloudflare.com; img-src 'self' data:; connect-src 'self'")
    if flask_app.config.get("SESSION_COOKIE_SECURE"):
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


# ─── Cloudflare Turnstile ─────────────────────────────────────────────────────

def verify_turnstile(token):
    if not CF_SITE_KEY and not CF_SECRET_KEY:
        return True
    if not CF_SITE_KEY or not CF_SECRET_KEY or not token:
        return False
    try:
        payload = urllib.parse.urlencode({"secret": CF_SECRET_KEY, "response": token}).encode()
        req = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=payload,
            headers={"User-Agent": "Sulav-VPS/4"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return bool(json.loads(resp.read()).get("success", False))
    except Exception:
        return False


# ─── Auth decorators ──────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("username"):
            return redirect(url_for("login"))
        data = load_data()
        s = data.get("settings", {})
        if s.get("maintenance") and session.get("username") != "__admin__":
            return render_template("maintenance.html",
                                   message=s.get("maintenance_msg", "Under maintenance"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin"):
            return redirect(f"/{ADMIN_PATH}/login")
        return f(*args, **kwargs)
    return decorated


def allocate_port(servers):
    used = {int(cfg.get("port", 0)) for cfg in servers.values()}
    for _ in range(100):
        candidate = 5001 + secrets.randbelow(54999)
        if candidate in used:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("127.0.0.1", candidate))
                return candidate
            except OSError:
                continue
    raise RuntimeError("Could not allocate a free service port")


# ─── Process helpers ──────────────────────────────────────────────────────────

def is_process_alive(pid):
    try:
        p = psutil.Process(pid)
        return p.is_running() and p.status() != psutil.STATUS_ZOMBIE
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False

def kill_process(pid):
    try:
        p = psutil.Process(pid)
        children = p.children(recursive=True)
        p.terminate()
        for c in children:
            try: c.terminate()
            except: pass
        try: p.wait(timeout=5)
        except psutil.TimeoutExpired: p.kill()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

def get_run_command(name, runtime, main_file):
    ext = Path(main_file).suffix.lower()
    if runtime == "node" or ext in (".js", ".ts", ".mjs"):
        return ["node", main_file]
    return [str(ensure_project_venv(name)), "-u", main_file]

def _sync_process_status():
    data = load_data()
    changed = False
    for name, cfg in data["servers"].items():
        pid = cfg.get("pid")
        if pid and not is_process_alive(pid):
            cfg["status"] = "stopped"; cfg["pid"] = None; changed = True
    if changed: save_data(data)

_sync_process_status()


# ─── Auto-restart ─────────────────────────────────────────────────────────────

def _do_auto_restart(name):
    data = load_data()
    cfg = data["servers"].get(name)
    if not cfg or not cfg.get("auto_restart"): return
    if name in RUNNING_PROCESSES:
        entry = RUNNING_PROCESSES[name]
        proc = entry["proc"]
        try: os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except:
            try: proc.terminate()
            except: pass
        try: proc.wait(timeout=5)
        except:
            try: proc.kill()
            except: pass
        try: entry["log_file"].close()
        except: pass
        del RUNNING_PROCESSES[name]
    elif cfg.get("pid"): kill_process(cfg["pid"])
    cfg["status"] = "stopped"; cfg["pid"] = None
    data["servers"][name] = cfg; save_data(data)
    log_path = project_dir(name) / "logs.txt"
    try:
        with open(log_path, "a") as lf:
            lf.write(f"[{datetime.now().isoformat()}] [AUTO-RESTART] Restarting...\n")
    except: pass
    main_file   = cfg.get("main_file") or "main.py"
    extract_dir = project_dir(name) / "extracted"
    if not (extract_dir / main_file).exists(): return
    cmd = get_run_command(name, cfg.get("runtime", "python"), main_file)
    env = runtime_environment(name); env["PORT"] = str(cfg.get("port", 8080))
    try:
        lf   = open(log_path, "a")
        proc = subprocess.Popen(cmd, cwd=str(extract_dir),
                                stdout=lf, stderr=lf, env=env, preexec_fn=os.setsid)
        RUNNING_PROCESSES[name] = {"proc": proc, "log_file": lf}
        data = load_data()
        data["servers"][name]["status"] = "running"
        data["servers"][name]["pid"]    = proc.pid
        save_data(data)
    except Exception as e:
        try:
            with open(log_path, "a") as lf2:
                lf2.write(f"[AUTO-RESTART ERROR] {e}\n")
        except: pass
        return
    _schedule_auto_restart(name)

def _schedule_auto_restart(name):
    if name in AUTO_RESTART_TIMERS: AUTO_RESTART_TIMERS[name].cancel()
    data = load_data()
    cfg  = data["servers"].get(name, {})
    if not cfg.get("auto_restart"): return
    interval = int(cfg.get("auto_restart_interval", 3600))
    t = threading.Timer(interval, _do_auto_restart, args=[name])
    t.daemon = True; t.start()
    AUTO_RESTART_TIMERS[name] = t

def _restore_auto_restarts():
    data = load_data()
    for name, cfg in data["servers"].items():
        if cfg.get("auto_restart") and cfg.get("status") == "running":
            _schedule_auto_restart(name)

if not IS_VERCEL:
    _restore_auto_restarts()


# ─── Package auto-detection ───────────────────────────────────────────────────

def detect_and_install_packages(name, extract_dir):
    if IS_VERCEL:
        return [], ["Vercel Functions cannot persist per-project virtual environments; deploy dependencies with this package instead."]
    installed, errors = [], []
    req_file = extract_dir / "requirements.txt"
    pkg_file = extract_dir / "package.json"
    if req_file.exists():
        try:
            pip = pip_command(name)
            subprocess.run(pip + ["install", "--upgrade", "pip", "setuptools", "wheel"],
                           capture_output=True, text=True, timeout=180)
            result = subprocess.run(
                pip + ["install", "--no-cache-dir", "--prefer-binary", "-r", str(req_file)],
                capture_output=True, text=True, timeout=300, cwd=str(extract_dir),
            )
            if result.returncode == 0:
                lines = [l.strip() for l in req_file.read_text(encoding="utf-8").splitlines()
                         if l.strip() and not l.lstrip().startswith("#")]
                installed.extend(lines)
                data = load_data(); cfg = data["servers"].get(name, {})
                for line in lines:
                    pname = re.split(r"[<>=!~;\[]", line, maxsplit=1)[0].strip()
                    if pname:
                        pkgs = [p for p in cfg.get("packages", []) if p.get("name") != pname]
                        pkgs.append({"name": pname, "version": "", "installed_at": datetime.now().isoformat()})
                        cfg["packages"] = pkgs
                data["servers"][name] = cfg; save_data(data)
            else:
                errors.append(f"pip: {(result.stderr or result.stdout)[-500:]}")
        except Exception as exc:
            errors.append(f"python environment: {exc}")
    if pkg_file.exists():
        try:
            result = subprocess.run(
                ["npm", "install", "--no-audit", "--no-fund"],
                capture_output=True, text=True, timeout=300, cwd=str(extract_dir),
                env=runtime_environment(name),
            )
            if result.returncode == 0:
                installed.append("npm packages")
            else:
                errors.append(f"npm: {(result.stderr or result.stdout)[-500:]}")
        except FileNotFoundError:
            errors.append("npm is not installed on this host")
        except Exception as exc:
            errors.append(f"npm: {exc}")
    return installed, errors


# ─── Auth routes ──────────────────────────────────────────────────────────────

@flask_app.route("/")
def index():
    if session.get("username"): return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@flask_app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        token = request.form.get("cf-turnstile-response", "")
        if not verify_turnstile(token):
            return render_template("login.html", error="Human verification failed.")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
            return render_template("login.html", error="Use 3–32 letters, numbers, dots, dashes, or underscores.")
        if len(password) < 8:
            return render_template("login.html", error="Password must be at least 8 characters.")
        data = load_data(); user = data["users"].get(username)
        if user:
            stored = user.get("password_hash", "")
            if not password_matches(stored, password):
                return render_template("login.html", error="Incorrect password")
            if not stored.startswith(("scrypt:", "pbkdf2:", "argon2:")):
                data["users"][username]["password_hash"] = hash_password(password)
                save_data(data)
        else:
            data["users"][username] = {
                "joined": datetime.now().isoformat(),
                "password_hash": hash_password(password),
            }
            save_data(data)
        session.clear()
        session["username"] = username
        session["csrf_token"] = secrets.token_urlsafe(32)
        return redirect(url_for("dashboard"))
    return render_template("login.html", error=None)


@flask_app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))


# ─── Dashboard ────────────────────────────────────────────────────────────────

@flask_app.route("/dashboard")
@login_required
def dashboard():
    username = session["username"]
    data = load_data()
    user_servers = {k: v for k, v in data["servers"].items() if v.get("owner") == username}
    changed = False
    for name, cfg in user_servers.items():
        pid = cfg.get("pid")
        if pid and not is_process_alive(pid):
            cfg["status"] = "stopped"; cfg["pid"] = None
            data["servers"][name] = cfg; changed = True
    if changed: save_data(data)
    running = sum(1 for v in user_servers.values() if v.get("status") == "running")
    return render_template("dashboard.html", servers=user_servers,
                           running=running, total=len(user_servers), username=username)


# ─── System stats ─────────────────────────────────────────────────────────────

@flask_app.route("/api/stats")
@login_required
def system_stats():
    cpu  = psutil.cpu_percent(interval=0.2)
    ram  = psutil.virtual_memory().percent
    disk = psutil.disk_usage("/").percent
    return jsonify({"cpu": cpu, "ram": ram, "disk": disk})


# ─── Server management ────────────────────────────────────────────────────────

@flask_app.route("/server/create", methods=["POST"])
@login_required
def create_server():
    raw_name = request.form.get("name", "").strip().replace(" ", "-")
    name = re.sub(r"[^A-Za-z0-9_-]", "", raw_name)[:48]
    runtime = request.form.get("runtime", "python") if request.form.get("runtime") in {"python", "node"} else "python"
    if not name: return redirect(url_for("dashboard"))
    data = load_data()
    if name in data["servers"]: return redirect(url_for("dashboard"))
    data["servers"][name] = {
        "name": name, "owner": session["username"], "runtime": runtime,
        "status": "stopped", "main_file": "", "port": allocate_port(data["servers"]),
        "packages": [], "pid": None, "created": datetime.now().isoformat(),
        "auto_restart": False, "auto_restart_interval": 3600
    }
    save_data(data)
    (SERVERS_DIR / name / "extracted").mkdir(parents=True, exist_ok=True)
    return redirect(url_for("server_detail", name=name))

@flask_app.route("/server/delete/<name>", methods=["POST"])
@login_required
def delete_server(name):
    data = load_data(); cfg = data["servers"].get(name)
    if cfg and (cfg.get("owner") == session["username"] or session.get("admin")):
        pid = cfg.get("pid")
        if pid: kill_process(pid)
        if name in RUNNING_PROCESSES:
            try: RUNNING_PROCESSES[name]["proc"].terminate()
            except: pass
            del RUNNING_PROCESSES[name]
        if name in AUTO_RESTART_TIMERS:
            AUTO_RESTART_TIMERS[name].cancel(); del AUTO_RESTART_TIMERS[name]
        del data["servers"][name]; save_data(data)
        shutil.rmtree(SERVERS_DIR / name, ignore_errors=True)
    return redirect(url_for("dashboard"))

@flask_app.route("/server/<name>")
@login_required
def server_detail(name):
    data = load_data(); cfg = data["servers"].get(name)
    if not cfg: return "Server not found", 404
    pid = cfg.get("pid")
    if pid and not is_process_alive(pid):
        cfg["status"] = "stopped"; cfg["pid"] = None
        data["servers"][name] = cfg; save_data(data)
    extract_dir = project_dir(name) / "extracted"
    return render_template("server.html", server_name=name, config=cfg,
                           files=list_files(extract_dir))

def list_files(directory, base=""):
    result = []
    if not directory.exists(): return result
    try:
        for entry in sorted(directory.iterdir(), key=lambda e: (e.is_file(), e.name)):
            rel = f"{base}/{entry.name}" if base else entry.name
            if entry.is_dir():
                result.append({"name": entry.name, "path": rel, "type": "dir", "size": 0})
                result.extend(list_files(entry, rel))
            else:
                result.append({"name": entry.name, "path": rel, "type": "file",
                               "size": entry.stat().st_size})
    except: pass
    return result


# ─── Upload ───────────────────────────────────────────────────────────────────

@flask_app.route("/server/<name>/upload", methods=["POST"])
@login_required
def upload_file(name):
    data = load_data(); cfg = data["servers"].get(name)
    if not cfg: return jsonify({"success": False, "error": "Not found"}), 404
    if "file" not in request.files: return jsonify({"success": False, "error": "No file"})
    upload = request.files["file"]
    filename = secure_filename(upload.filename or "")
    if not filename: return jsonify({"success": False, "error": "Invalid filename"})
    extract_dir = project_dir(name) / "extracted"
    extract_dir.mkdir(parents=True, exist_ok=True)
    upload_path = project_dir(name) / f"upload_{secrets.token_hex(8)}_{filename}"
    upload.save(upload_path)
    extracted = []
    try:
        if filename.lower().endswith(".zip"):
            total_size = 0
            with zipfile.ZipFile(upload_path, "r") as archive:
                members = [m for m in archive.infolist() if not m.is_dir()]
                if len(members) > MAX_ZIP_FILES:
                    raise ValueError(f"ZIP contains too many files (limit {MAX_ZIP_FILES})")
                for member in members:
                    if member.filename.startswith("/") or ".." in Path(member.filename).parts:
                        raise ValueError("ZIP contains an unsafe path")
                    mode = (member.external_attr >> 16) & 0o170000
                    if mode == 0o120000:
                        raise ValueError("ZIP symlinks are not allowed")
                    total_size += member.file_size
                    if total_size > MAX_ZIP_UNCOMPRESSED_BYTES:
                        raise ValueError("ZIP is too large after extraction")
                    target = safe_path(extract_dir, member.filename)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(member, "r") as src, target.open("wb") as dst:
                        shutil.copyfileobj(src, dst, length=1024 * 1024)
                    extracted.append(str(Path(member.filename)))
            if not cfg.get("main_file"):
                for candidate in ["main.py", "app.py", "bot.py", "index.js", "main.js"]:
                    if (extract_dir / candidate).exists():
                        cfg["main_file"] = candidate
                        break
        else:
            if not filename.lower().endswith((".py", ".js", ".ts", ".mjs", ".json", ".txt", ".md", ".toml", ".yaml", ".yml")):
                return jsonify({"success": False, "error": "File type not allowed"})
            dest = safe_path(extract_dir, filename)
            shutil.copyfile(upload_path, dest)
            extracted = [filename]
            if not cfg.get("main_file") and filename.lower().endswith((".py", ".js", ".ts", ".mjs")):
                cfg["main_file"] = filename
        data["servers"][name] = cfg; save_data(data)
        installed, errors = detect_and_install_packages(name, extract_dir)
        return jsonify({"success": True, "files": extracted, "auto_installed": installed, "install_errors": errors})
    except (ValueError, zipfile.BadZipFile, OSError) as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    finally:
        upload_path.unlink(missing_ok=True)


@flask_app.route("/server/<name>/auto-install", methods=["POST"])
@login_required
def auto_install(name):
    data = load_data(); cfg = data["servers"].get(name)
    if not cfg: return jsonify({"success": False, "error": "Not found"}), 404
    extract_dir = project_dir(name) / "extracted"
    installed, errors = detect_and_install_packages(name, extract_dir)
    return jsonify({"success": True, "installed": installed, "errors": errors})


# ─── Console ──────────────────────────────────────────────────────────────────

@flask_app.route("/server/<name>/console", methods=["POST"])
@login_required
def console_exec(name):
    if not ALLOW_CONSOLE:
        return jsonify({"output": "", "error": "Console is disabled. Set ENABLE_SERVER_CONSOLE=true on a trusted VPS.", "code": 1}), 403
    data = load_data(); cfg = data["servers"].get(name)
    if not cfg: return jsonify({"output": "", "error": "Server not found", "code": 1}), 404
    if cfg.get("owner") != session["username"]:
        return jsonify({"output": "", "error": "Access denied", "code": 1}), 403
    cmd_text = ((request.get_json(silent=True) or {}).get("command") or "").strip()
    if not cmd_text: return jsonify({"output": "", "error": "", "code": 0})
    if len(cmd_text) > 500 or any(op in cmd_text for op in [";", "&&", "||", "|", ">", "<", "`", "$ (", "${"]):
        return jsonify({"output": "", "error": "Shell operators are disabled", "code": 1})
    try:
        args = shlex.split(cmd_text)
    except ValueError as exc:
        return jsonify({"output": "", "error": str(exc), "code": 1})
    allowed = {"pwd", "ls", "find", "cat", "head", "tail", "grep", "echo", "whoami", "python", "pip", "node", "npm", "git", "ps", "du"}
    if not args or Path(args[0]).name not in allowed:
        return jsonify({"output": "", "error": "Command is not allowed", "code": 1})
    if any(flag in {"-c", "-e", "--eval", "--exec"} for flag in args):
        return jsonify({"output": "", "error": "Inline code execution is disabled", "code": 1})
    extract_dir = project_dir(name) / "extracted"
    try:
        result = subprocess.run(args, shell=False, capture_output=True, text=True, timeout=30,
                                cwd=str(extract_dir), env=runtime_environment(name))
        return jsonify({"output": result.stdout[-20000:], "error": result.stderr[-10000:], "code": result.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({"output": "", "error": "Timed out (30s limit)", "code": -1})
    except Exception as exc:
        return jsonify({"output": "", "error": str(exc), "code": -1})


# ─── Packages ─────────────────────────────────────────────────────────────────

@flask_app.route("/server/<name>/packages/install", methods=["POST"])
@login_required
def install_package(name):
    if IS_VERCEL:
        return jsonify({"success": False, "error": "Install project dependencies during Vercel build; runtime package installs are not persistent."}), 409
    data = load_data(); cfg = data["servers"].get(name)
    if not cfg: return jsonify({"success": False, "error": "Not found"}), 404
    payload = request.get_json(silent=True) or {}
    pkg_name = str(payload.get("name", "")).strip()
    pkg_ver = str(payload.get("version", "")).strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", pkg_name):
        return jsonify({"success": False, "error": "Invalid package name"}), 400
    if pkg_ver and not re.fullmatch(r"[A-Za-z0-9.*+!<>=~ ,;_-]{1,80}", pkg_ver):
        return jsonify({"success": False, "error": "Invalid package version"}), 400
    install_str = f"{pkg_name}=={pkg_ver}" if pkg_ver else pkg_name
    try:
        result = subprocess.run(pip_command(name) + ["install", "--no-cache-dir", "--prefer-binary", install_str],
                                capture_output=True, text=True, timeout=300,
                                cwd=str(project_dir(name) / "extracted"))
        if result.returncode != 0:
            return jsonify({"success": False, "error": (result.stderr or result.stdout)[-600:]})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)})
    pkgs = [p for p in cfg.get("packages", []) if p.get("name") != pkg_name]
    pkgs.append({"name": pkg_name, "version": pkg_ver or "", "installed_at": datetime.now().isoformat()})
    cfg["packages"] = pkgs; data["servers"][name] = cfg; save_data(data)
    req_path = project_dir(name) / "extracted" / "requirements.txt"
    try:
        lines = req_path.read_text(encoding="utf-8").splitlines() if req_path.exists() else []
        lines = [l for l in lines if re.split(r"[<>=!~;\[]", l.strip(), maxsplit=1)[0].lower() != pkg_name.lower()]
        lines.append(install_str); req_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError:
        pass
    return jsonify({"success": True, "package": pkg_name})


@flask_app.route("/server/<name>/packages/remove", methods=["POST"])
@login_required
def remove_package(name):
    data = load_data(); cfg = data["servers"].get(name)
    if not cfg: return jsonify({"success": False}), 404
    pkg_name = (request.get_json(silent=True) or {}).get("name", "")
    cfg["packages"] = [p for p in cfg.get("packages", []) if p.get("name") != pkg_name]
    data["servers"][name] = cfg; save_data(data)
    return jsonify({"success": True})


# ─── Settings ─────────────────────────────────────────────────────────────────

@flask_app.route("/server/<name>/settings", methods=["POST"])
@login_required
def save_settings(name):
    data = load_data(); cfg = data["servers"].get(name)
    if not cfg: return jsonify({"success": False, "error": "Not found"}), 404
    payload = request.get_json(silent=True) or {}
    main_file = str(payload.get("main_file", cfg.get("main_file", ""))).strip().replace("\\", "/")
    if main_file and (Path(main_file).is_absolute() or ".." in Path(main_file).parts):
        return jsonify({"success": False, "error": "Invalid main file path"}), 400
    try:
        port = int(payload.get("port", cfg.get("port", 8080)))
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Port must be a number"}), 400
    if not 1024 <= port <= 65535:
        return jsonify({"success": False, "error": "Port must be between 1024 and 65535"}), 400
    if any(other != name and int(other_cfg.get("port", 0)) == port for other, other_cfg in data["servers"].items()):
        return jsonify({"success": False, "error": "That port is already assigned to another project"}), 400
    cfg["main_file"]             = main_file
    cfg["port"]                  = port
    cfg["auto_restart"]          = payload.get("auto_restart", cfg.get("auto_restart", False))
    try:
        restart_interval = int(payload.get("auto_restart_interval", cfg.get("auto_restart_interval", 3600)))
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Restart interval must be a number"}), 400
    cfg["auto_restart_interval"] = max(60, min(restart_interval, 604800))
    data["servers"][name] = cfg; save_data(data)
    if cfg["auto_restart"] and cfg.get("status") == "running":
        _schedule_auto_restart(name)
    elif not cfg["auto_restart"] and name in AUTO_RESTART_TIMERS:
        AUTO_RESTART_TIMERS[name].cancel(); del AUTO_RESTART_TIMERS[name]
    return jsonify({"success": True})


# ─── Start / Stop ─────────────────────────────────────────────────────────────

@flask_app.route("/server/<name>/start", methods=["POST"])
@login_required
def start_server(name):
    if IS_VERCEL:
        return jsonify({"success": False, "error": "Vercel Functions cannot run 24×7 child processes. Deploy this package on a VPS for hosted services."}), 409
    data = load_data(); cfg = data["servers"].get(name)
    if not cfg: return jsonify({"success": False, "error": "Not found"}), 404
    pid = cfg.get("pid")
    if pid and is_process_alive(pid): return jsonify({"success": False, "error": "Already running"})
    main_file   = cfg.get("main_file") or "main.py"
    extract_dir = project_dir(name) / "extracted"
    try:
        main_path = safe_path(extract_dir, main_file)
    except ValueError:
        return jsonify({"success": False, "error": "Invalid main file path"}), 400
    if not main_path.exists() or not main_path.is_file():
        return jsonify({"success": False, "error": f"{main_file} not found. Upload files first."})
    log_path = project_dir(name) / "logs.txt"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = get_run_command(name, cfg.get("runtime", "python"), main_file)
    env = runtime_environment(name); env["PORT"] = str(cfg.get("port", 8080))
    try:
        with open(log_path, "a") as lf:
            lf.write(f"\n{'='*50}\n[{datetime.now().isoformat()}] Starting: {' '.join(cmd)}\n{'='*50}\n")
        lf   = open(log_path, "a")
        proc = subprocess.Popen(cmd, cwd=str(extract_dir), stdout=lf, stderr=lf,
                                env=env, preexec_fn=os.setsid)
        RUNNING_PROCESSES[name] = {"proc": proc, "log_file": lf}
        cfg["status"] = "running"; cfg["pid"] = proc.pid
        data["servers"][name] = cfg; save_data(data)
        if cfg.get("auto_restart"): _schedule_auto_restart(name)
        return jsonify({"success": True, "pid": proc.pid})
    except Exception as e: return jsonify({"success": False, "error": str(e)})

@flask_app.route("/server/<name>/stop", methods=["POST"])
@login_required
def stop_server(name):
    data = load_data(); cfg = data["servers"].get(name)
    if not cfg: return jsonify({"success": False}), 404
    if name in AUTO_RESTART_TIMERS:
        AUTO_RESTART_TIMERS[name].cancel(); del AUTO_RESTART_TIMERS[name]
    stopped = False
    if name in RUNNING_PROCESSES:
        entry = RUNNING_PROCESSES[name]; proc = entry["proc"]
        try: os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except:
            try: proc.terminate()
            except: pass
        try: proc.wait(timeout=5)
        except:
            try: proc.kill()
            except: pass
        try: entry["log_file"].close()
        except: pass
        del RUNNING_PROCESSES[name]; stopped = True
    if cfg.get("pid") and not stopped: kill_process(cfg["pid"])
    log_path = project_dir(name) / "logs.txt"
    try:
        with open(log_path, "a") as lf:
            lf.write(f"[{datetime.now().isoformat()}] Server stopped\n")
    except: pass
    cfg["status"] = "stopped"; cfg["pid"] = None
    data["servers"][name] = cfg; save_data(data)
    return jsonify({"success": True})


# ─── Local hosted-service gateway ─────────────────────────────────────────────

@flask_app.route("/<int:port>/", defaults={"subpath": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
@flask_app.route("/<int:port>/<path:subpath>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def hosted_service_gateway(port, subpath):
    if IS_VERCEL:
        return jsonify({"error": "Dynamic child ports are not available in Vercel serverless functions. Use the VPS deployment instructions."}), 409
    data = load_data()
    cfg = next((v for v in data["servers"].values() if int(v.get("port", 0)) == port), None)
    if not cfg or cfg.get("status") != "running":
        return jsonify({"error": "No running service is assigned to this port"}), 404
    target = f"http://127.0.0.1:{port}/{subpath}"
    if request.query_string:
        target += "?" + request.query_string.decode("utf-8", "ignore")
    headers = {k: v for k, v in request.headers.items() if k.lower() not in {"host", "content-length"}}
    try:
        upstream = urllib.request.Request(target, data=request.get_data() or None, headers=headers, method=request.method)
        with urllib.request.urlopen(upstream, timeout=15) as response:
            body = response.read(MAX_UPLOAD_BYTES)
            excluded = {"content-encoding", "transfer-encoding", "content-length", "connection"}
            out_headers = [(k, v) for k, v in response.headers.items() if k.lower() not in excluded]
            return Response(body, status=response.status, headers=out_headers)
    except urllib.error.HTTPError as exc:
        return Response(exc.read(), status=exc.code, content_type=exc.headers.get_content_type())
    except Exception as exc:
        return jsonify({"error": f"Service unavailable: {exc}"}), 502


# ─── Logs ─────────────────────────────────────────────────────────────────────

@flask_app.route("/server/<name>/logs")
@login_required
def get_logs(name):
    log_path = project_dir(name) / "logs.txt"
    if not log_path.exists():
        return jsonify({"logs": "No logs yet. Start the server to see output."})
    try:
        content = log_path.read_text(errors="replace")
        lines   = content.splitlines()
        if len(lines) > 200:
            lines   = lines[-200:]
            content = "... (last 200 lines) ...\n" + "\n".join(lines)
        return jsonify({"logs": content or "No output yet."})
    except Exception as e: return jsonify({"logs": f"Error reading logs: {e}"})

@flask_app.route("/server/<name>/logs/clear", methods=["POST"])
@login_required
def clear_logs(name):
    try:
        project_dir(name).joinpath("logs.txt").write_text("", encoding="utf-8")
    except (OSError, ValueError):
        return jsonify({"success": False, "error": "Project not found"}), 404
    return jsonify({"success": True})


# ─── Admin routes (secret path) ───────────────────────────────────────────────

def _admin_routes(flask_app):
    ap = ADMIN_PATH   # e.g. "Sulav"

    @flask_app.route(f"/{ap}/login", methods=["GET", "POST"])
    def admin_login():
        if request.method == "POST":
            if not ADMIN_PASSWORD:
                return render_template("admin_login.html", error="Admin access is not configured. Set ADMIN_PASSWORD.")
            token = request.form.get("cf-turnstile-response", "")
            if not verify_turnstile(token):
                return render_template("admin_login.html", error="Human verification failed.")
            pw = request.form.get("password", "")
            if hmac.compare_digest(pw, ADMIN_PASSWORD):
                session.clear()
                session["admin"] = True
                session["csrf_token"] = secrets.token_urlsafe(32)
                return redirect(f"/{ap}/panel")
            return render_template("admin_login.html", error="Wrong admin password")
        return render_template("admin_login.html", error=None)

    @flask_app.route(f"/{ap}/logout")
    def admin_logout():
        session.pop("admin", None); return redirect(url_for("login"))

    @flask_app.route(f"/{ap}/panel")
    @admin_required
    def admin_dashboard():
        data = load_data()
        servers  = data["servers"]; users_raw = data["users"]
        settings = data.get("settings", {})
        for name, cfg in servers.items():
            pid = cfg.get("pid")
            if pid and not is_process_alive(pid):
                cfg["status"] = "stopped"; cfg["pid"] = None
        running     = sum(1 for v in servers.values() if v.get("status") == "running")
        total_files = sum(
            sum(1 for f in (SERVERS_DIR / s / "extracted").rglob("*") if f.is_file())
            for s in servers if (SERVERS_DIR / s / "extracted").exists()
        )
        user_stats = []
        for u in users_raw:
            u_srv = [v for v in servers.values() if v.get("owner") == u]
            u_files = sum(
                sum(1 for f in (SERVERS_DIR / sv["name"] / "extracted").rglob("*") if f.is_file())
                for sv in u_srv if (SERVERS_DIR / sv["name"] / "extracted").exists()
            )
            user_stats.append({
                "username": u, "projects": len(u_srv),
                "running": sum(1 for sv in u_srv if sv.get("status") == "running"),
                "files": u_files, "joined": users_raw[u].get("joined", "")
            })
        return render_template("admin.html", users=user_stats, servers=servers,
                               settings=settings, total_users=len(users_raw),
                               total_projects=len(servers), running=running,
                               total_files=total_files,
                               security=security_snapshot(data),
                               current_ip=request.environ.get("client_ip", "unknown"))

    @flask_app.route(f"/{ap}/user/<username>/files")
    @admin_required
    def admin_user_files(username):
        data = load_data()
        user_servers = {k: v for k, v in data["servers"].items() if v.get("owner") == username}
        file_data = {n: {"config": c, "files": list_files(SERVERS_DIR / n / "extracted")}
                     for n, c in user_servers.items()}
        return render_template("admin_files.html", username=username, file_data=file_data)

    @flask_app.route(f"/{ap}/user/<username>/delete", methods=["POST"])
    @admin_required
    def admin_delete_user(username):
        data = load_data()
        to_delete = [k for k, v in data["servers"].items() if v.get("owner") == username]
        for name in to_delete:
            pid = data["servers"][name].get("pid")
            if pid: kill_process(pid)
            if name in RUNNING_PROCESSES:
                try: RUNNING_PROCESSES[name]["proc"].terminate()
                except: pass
                del RUNNING_PROCESSES[name]
            if name in AUTO_RESTART_TIMERS:
                AUTO_RESTART_TIMERS[name].cancel(); del AUTO_RESTART_TIMERS[name]
            shutil.rmtree(SERVERS_DIR / name, ignore_errors=True)
            del data["servers"][name]
        data["users"].pop(username, None); save_data(data)
        return redirect(f"/{ap}/panel")

    @flask_app.route(f"/{ap}/security")
    @admin_required
    def admin_security():
        return jsonify({"success": True, "current_ip": request.environ.get("client_ip", "unknown"), **security_snapshot(load_data())})

    @flask_app.route(f"/{ap}/security/ban", methods=["POST"])
    @admin_required
    def admin_ban_ip():
        payload = request.get_json() or {}
        ip = normalize_ip(payload.get("ip", ""))
        if ip == "unknown":
            return jsonify({"success": False, "error": "Enter a valid IPv4 or IPv6 address"}), 400
        if ip == request.environ.get("client_ip"):
            return jsonify({"success": False, "error": "You cannot ban the current admin IP"}), 400
        reason = str(payload.get("reason", "Manual administrator ban")).strip()[:200] or "Manual administrator ban"
        try:
            duration = max(0, min(int(payload.get("duration_minutes", 0)), 525600))
        except (TypeError, ValueError):
            duration = 0
        created = datetime.now()
        expires = (created + timedelta(minutes=duration)).isoformat(timespec="seconds") if duration else None
        data = load_data(); security = security_state(data)
        security["banned_ips"][ip] = {"reason": reason, "created_at": created.isoformat(timespec="seconds"), "expires_at": expires, "banned_by": "admin"}
        save_data(data)
        return jsonify({"success": True, "ip": ip, "expires_at": expires})

    @flask_app.route(f"/{ap}/security/unban", methods=["POST"])
    @admin_required
    def admin_unban_ip():
        ip = normalize_ip((request.get_json() or {}).get("ip", ""))
        data = load_data(); security = security_state(data)
        security["banned_ips"].pop(ip, None)
        save_data(data)
        return jsonify({"success": True, "ip": ip})

    @flask_app.route(f"/{ap}/maintenance", methods=["POST"])
    @admin_required
    def toggle_maintenance():
        data = load_data(); payload = request.get_json(silent=True) or {}
        data["settings"]["maintenance"]     = payload.get("enabled", False)
        data["settings"]["maintenance_msg"] = str(payload.get("message", "Under maintenance"))[:500]
        save_data(data); return jsonify({"success": True})

    @flask_app.route(f"/{ap}/theme", methods=["POST"])
    @admin_required
    def save_theme():
        data = load_data(); payload = request.get_json(silent=True) or {}
        color = str(payload.get("color", "#00ff41")).strip()
        if not re.fullmatch(r"#[0-9a-fA-F]{6}", color):
            return jsonify({"success": False, "error": "Invalid theme color"}), 400
        data["settings"]["accent_color"] = color
        save_data(data); return jsonify({"success": True})

    @flask_app.route(f"/{ap}/broadcast", methods=["POST"])
    @admin_required
    def save_broadcast():
        data = load_data(); payload = request.get_json(silent=True) or {}
        btype = payload.get("btype", "info")
        if btype not in {"info", "warning", "danger", "success"}:
            btype = "info"
        data["settings"]["broadcast"] = {
            "active":  payload.get("active", False),
            "message": str(payload.get("message", ""))[:500],
            "btype":   btype
        }
        save_data(data); return jsonify({"success": True})

    @flask_app.route(f"/{ap}/file/<project_name>/download")
    @admin_required
    def admin_download_file(project_name):
        file_path = request.args.get("path", "")
        if not file_path: abort(400)
        try:
            base = project_dir(project_name) / "extracted"
            safe_file = safe_path(base, file_path)
        except ValueError:
            abort(404)
        if not safe_file.exists() or safe_file.is_dir():
            abort(404)
        return send_file(safe_file, as_attachment=True, download_name=safe_file.name)

    @flask_app.route(f"/{ap}/project/<project_name>/download")
    @admin_required
    def admin_download_project(project_name):
        type_filter = request.args.get("type", "all")
        try:
            extract_dir = project_dir(project_name) / "extracted"
        except ValueError:
            abort(404)
        if not extract_dir.exists(): abort(404)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in extract_dir.rglob("*"):
                if f.is_file() and (type_filter == "all" or f.name.endswith(type_filter)):
                    zf.write(f, f.relative_to(extract_dir))
        buf.seek(0)
        ext_part = type_filter.replace(".", "") if type_filter != "all" else ""
        fname = f"{project_name}{'-' + ext_part if ext_part else ''}.zip"
        return send_file(buf, as_attachment=True, download_name=fname, mimetype="application/zip")

    @flask_app.route(f"/{ap}/user/<username>/download")
    @admin_required
    def admin_download_user(username):
        type_filter  = request.args.get("type", "all")
        data         = load_data()
        user_servers = {k: v for k, v in data["servers"].items() if v.get("owner") == username}
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name in user_servers:
                extract_dir = project_dir(name) / "extracted"
                if not extract_dir.exists(): continue
                for f in extract_dir.rglob("*"):
                    if f.is_file() and (type_filter == "all" or f.name.endswith(type_filter)):
                        zf.write(f, Path(name) / f.relative_to(extract_dir))
        buf.seek(0)
        ext_part = type_filter.replace(".", "") if type_filter != "all" else ""
        fname = f"{username}-files{'-' + ext_part if ext_part else ''}.zip"
        return send_file(buf, as_attachment=True, download_name=fname, mimetype="application/zip")

_admin_routes(flask_app)

# FastAPI is the public ASGI entrypoint. Mounting the existing Flask dashboard
# keeps the established UI/routes intact while Vercel and Uvicorn get ASGI.
app = FastAPI(title="Sulav VPS", docs_url=None, redoc_url=None)

@app.middleware("http")
async def api_security_headers(request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response

@app.get("/healthz")
def healthz():
    return JSONResponse({"ok": True, "service": "sulav-vps", "vercel": IS_VERCEL})

app.mount("/", WsgiToAsgi(flask_app))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), reload=False)
