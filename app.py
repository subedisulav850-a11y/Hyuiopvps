import os
import json
import signal
import subprocess
import shutil
import zipfile
import hashlib
import psutil
import threading
import urllib.request
import urllib.parse
from pathlib import Path
from functools import wraps
from datetime import datetime
from flask import (Flask, render_template, request, redirect, url_for,
                   session, jsonify, send_file, abort, Blueprint)
import io

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "Sulav-vps-secret-2025")

BASE_DIR = Path(__file__).parent
IS_VERCEL = bool(os.environ.get("VERCEL"))
RUNTIME_DIR = Path("/tmp/sulav-vps") if IS_VERCEL else BASE_DIR
DATA_FILE = RUNTIME_DIR / "data.json"
SERVERS_DIR = RUNTIME_DIR / "servers"
RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
SERVERS_DIR.mkdir(parents=True, exist_ok=True)
if IS_VERCEL and not DATA_FILE.exists():
    source_data = BASE_DIR / "data.json"
    if source_data.exists():
        try:
            DATA_FILE.write_text(source_data.read_text())
        except Exception:
            pass

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Password")
CF_SITE_KEY   = os.environ.get("CF_TURNSTILE_SITE_KEY", "")
CF_SECRET_KEY = os.environ.get("CF_TURNSTILE_SECRET_KEY", "")
ADMIN_PATH    = os.environ.get("ADMIN_PATH", "admin")   # secret URL segment
SITE_NAME     = "Sulav VPS"

RUNNING_PROCESSES  = {}
AUTO_RESTART_TIMERS = {}


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
    DATA_FILE.write_text(json.dumps(data, indent=2, default=str))

def hash_password(p):
    return hashlib.sha256(p.encode()).hexdigest()


# ─── Context processor — inject theme/broadcast into every template ───────────

@app.context_processor
def inject_globals():
    data = load_data()
    s = data.get("settings", {})
    return {
        "site_name":    SITE_NAME,
        "theme_color":  s.get("accent_color", "#00ff41"),
        "broadcast":    s.get("broadcast", {}),
        "admin_path":   ADMIN_PATH,
        "cf_site_key":  CF_SITE_KEY,
    }


# ─── Cloudflare Turnstile ─────────────────────────────────────────────────────

def verify_turnstile(token):
    if not CF_SECRET_KEY:
        return True
    if not token:
        return False
    try:
        data = urllib.parse.urlencode({"secret": CF_SECRET_KEY, "response": token}).encode()
        req  = urllib.request.Request(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify", data=data)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read()).get("success", False)
    except Exception:
        return True


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

def get_run_command(runtime, main_file):
    ext = Path(main_file).suffix.lower()
    if runtime == "node" or ext in (".js", ".ts", ".mjs"):
        return ["node", main_file]
    return ["python", "-u", main_file]

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
    log_path = SERVERS_DIR / name / "logs.txt"
    try:
        with open(log_path, "a") as lf:
            lf.write(f"[{datetime.now().isoformat()}] [AUTO-RESTART] Restarting...\n")
    except: pass
    main_file   = cfg.get("main_file") or "main.py"
    extract_dir = SERVERS_DIR / name / "extracted"
    if not (extract_dir / main_file).exists(): return
    cmd = get_run_command(cfg.get("runtime", "python"), main_file)
    env = os.environ.copy(); env["PORT"] = str(cfg.get("port", 8080))
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

_restore_auto_restarts()


# ─── Package auto-detection ───────────────────────────────────────────────────

def detect_and_install_packages(name, extract_dir):
    installed, errors = [], []
    req_file = extract_dir / "requirements.txt"
    pkg_file = extract_dir / "package.json"
    if req_file.exists():
        try:
            result = subprocess.run(["pip", "install", "-r", str(req_file)],
                                    capture_output=True, text=True, timeout=180)
            if result.returncode == 0:
                lines = [l.strip() for l in req_file.read_text().splitlines()
                         if l.strip() and not l.startswith("#")]
                installed.extend(lines)
                data = load_data(); cfg = data["servers"].get(name, {})
                for line in lines:
                    pname = line.split("==")[0].split(">=")[0].split("<=")[0].split("~=")[0].strip()
                    if pname:
                        pkgs = [p for p in cfg.get("packages", []) if p["name"] != pname]
                        pkgs.append({"name": pname, "version": "", "installed_at": datetime.now().isoformat()})
                        cfg["packages"] = pkgs
                data["servers"][name] = cfg; save_data(data)
            else: errors.append(f"pip: {result.stderr[:200]}")
        except Exception as e: errors.append(str(e))
    if pkg_file.exists():
        try:
            result = subprocess.run(["npm", "install"], capture_output=True, text=True,
                                    timeout=180, cwd=str(extract_dir))
            if result.returncode == 0: installed.append("npm packages")
            else: errors.append(f"npm: {result.stderr[:200]}")
        except Exception as e: errors.append(str(e))
    return installed, errors


# ─── Auth routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if session.get("username"): return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        token = request.form.get("cf-turnstile-response", "")
        if CF_SITE_KEY and not verify_turnstile(token):
            return render_template("login.html", error="Human verification failed.")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if not username:
            return render_template("login.html", error="Username required")
        data = load_data(); user = data["users"].get(username)
        if user:
            stored = user.get("password_hash", "")
            if stored and stored != hash_password(password):
                return render_template("login.html", error="Incorrect password")
            elif not stored and password:
                data["users"][username]["password_hash"] = hash_password(password)
                save_data(data)
        else:
            data["users"][username] = {
                "joined": datetime.now().isoformat(),
                "password_hash": hash_password(password) if password else ""
            }
            save_data(data)
        session["username"] = username
        return redirect(url_for("dashboard"))
    return render_template("login.html", error=None)

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))


# ─── Dashboard ────────────────────────────────────────────────────────────────

@app.route("/dashboard")
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

@app.route("/api/stats")
@login_required
def system_stats():
    cpu  = psutil.cpu_percent(interval=0.2)
    ram  = psutil.virtual_memory().percent
    disk = psutil.disk_usage("/").percent
    return jsonify({"cpu": cpu, "ram": ram, "disk": disk})


# ─── Server management ────────────────────────────────────────────────────────

@app.route("/server/create", methods=["POST"])
@login_required
def create_server():
    name    = request.form.get("name", "").strip().replace(" ", "-")
    runtime = request.form.get("runtime", "python")
    if not name: return redirect(url_for("dashboard"))
    data = load_data()
    if name in data["servers"]: return redirect(url_for("dashboard"))
    data["servers"][name] = {
        "name": name, "owner": session["username"], "runtime": runtime,
        "status": "stopped", "main_file": "", "port": 8080,
        "packages": [], "pid": None, "created": datetime.now().isoformat(),
        "auto_restart": False, "auto_restart_interval": 3600
    }
    save_data(data)
    (SERVERS_DIR / name / "extracted").mkdir(parents=True, exist_ok=True)
    return redirect(url_for("server_detail", name=name))

@app.route("/server/delete/<name>", methods=["POST"])
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

@app.route("/server/<name>")
@login_required
def server_detail(name):
    data = load_data(); cfg = data["servers"].get(name)
    if not cfg: return "Server not found", 404
    pid = cfg.get("pid")
    if pid and not is_process_alive(pid):
        cfg["status"] = "stopped"; cfg["pid"] = None
        data["servers"][name] = cfg; save_data(data)
    extract_dir = SERVERS_DIR / name / "extracted"
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

@app.route("/server/<name>/upload", methods=["POST"])
@login_required
def upload_file(name):
    data = load_data(); cfg = data["servers"].get(name)
    if not cfg: return jsonify({"success": False, "error": "Not found"}), 404
    if "file" not in request.files: return jsonify({"success": False, "error": "No file"})
    f = request.files["file"]
    extract_dir = SERVERS_DIR / name / "extracted"
    extract_dir.mkdir(parents=True, exist_ok=True)
    upload_path = SERVERS_DIR / name / f"upload_{f.filename}"
    f.save(upload_path)
    extracted = []
    if f.filename.endswith(".zip"):
        try:
            with zipfile.ZipFile(upload_path, "r") as z:
                z.extractall(extract_dir)
                extracted = [m.filename for m in z.infolist() if not m.is_dir()]
            upload_path.unlink(missing_ok=True)
            if not cfg.get("main_file"):
                for fname in ["main.py", "app.py", "bot.py", "index.js", "main.js"]:
                    if (extract_dir / fname).exists():
                        cfg["main_file"] = fname
                        data["servers"][name] = cfg; save_data(data); break
        except Exception as e: return jsonify({"success": False, "error": str(e)})
    else:
        dest = extract_dir / f.filename
        shutil.copy(upload_path, dest); upload_path.unlink(missing_ok=True)
        extracted = [f.filename]
        if not cfg.get("main_file") and f.filename.endswith((".py", ".js", ".ts")):
            cfg["main_file"] = f.filename; data["servers"][name] = cfg; save_data(data)
    installed, errors = detect_and_install_packages(name, extract_dir)
    return jsonify({"success": True, "files": extracted,
                    "auto_installed": installed, "install_errors": errors})

@app.route("/server/<name>/auto-install", methods=["POST"])
@login_required
def auto_install(name):
    data = load_data(); cfg = data["servers"].get(name)
    if not cfg: return jsonify({"success": False, "error": "Not found"}), 404
    extract_dir = SERVERS_DIR / name / "extracted"
    installed, errors = detect_and_install_packages(name, extract_dir)
    return jsonify({"success": True, "installed": installed, "errors": errors})


# ─── Console ──────────────────────────────────────────────────────────────────

@app.route("/server/<name>/console", methods=["POST"])
@login_required
def console_exec(name):
    data = load_data(); cfg = data["servers"].get(name)
    if not cfg: return jsonify({"output": "", "error": "Server not found", "code": 1}), 404
    if cfg.get("owner") != session["username"]:
        return jsonify({"output": "", "error": "Access denied", "code": 1}), 403
    payload = request.get_json()
    cmd = (payload or {}).get("command", "").strip()
    if not cmd: return jsonify({"output": "", "error": "", "code": 0})
    extract_dir = SERVERS_DIR / name / "extracted"
    extract_dir.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=30, cwd=str(extract_dir)
        )
        return jsonify({"output": result.stdout, "error": result.stderr, "code": result.returncode})
    except subprocess.TimeoutExpired:
        return jsonify({"output": "", "error": "Timed out (30s limit)", "code": -1})
    except Exception as e:
        return jsonify({"output": "", "error": str(e), "code": -1})


# ─── Packages ─────────────────────────────────────────────────────────────────

@app.route("/server/<name>/packages/install", methods=["POST"])
@login_required
def install_package(name):
    data = load_data(); cfg = data["servers"].get(name)
    if not cfg: return jsonify({"success": False, "error": "Not found"}), 404
    payload  = request.get_json()
    pkg_name = payload.get("name", "").strip()
    pkg_ver  = payload.get("version", "").strip()
    if not pkg_name: return jsonify({"success": False, "error": "Package name required"})
    install_str = f"{pkg_name}=={pkg_ver}" if pkg_ver else pkg_name
    try:
        result = subprocess.run(["pip", "install", install_str],
                                capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            return jsonify({"success": False, "error": result.stderr[:400] or result.stdout[:400]})
    except Exception as e: return jsonify({"success": False, "error": str(e)})
    pkgs = [p for p in cfg.get("packages", []) if p["name"] != pkg_name]
    pkgs.append({"name": pkg_name, "version": pkg_ver or "",
                 "installed_at": datetime.now().isoformat()})
    cfg["packages"] = pkgs; data["servers"][name] = cfg; save_data(data)
    req_path = SERVERS_DIR / name / "extracted" / "requirements.txt"
    try:
        lines = req_path.read_text().splitlines() if req_path.exists() else []
        lines = [l for l in lines if not l.lower().startswith(pkg_name.lower())]
        lines.append(install_str); req_path.write_text("\n".join(lines) + "\n")
    except: pass
    return jsonify({"success": True, "package": pkg_name})

@app.route("/server/<name>/packages/remove", methods=["POST"])
@login_required
def remove_package(name):
    data = load_data(); cfg = data["servers"].get(name)
    if not cfg: return jsonify({"success": False}), 404
    pkg_name = (request.get_json() or {}).get("name", "")
    cfg["packages"] = [p for p in cfg.get("packages", []) if p["name"] != pkg_name]
    data["servers"][name] = cfg; save_data(data)
    return jsonify({"success": True})


# ─── Settings ─────────────────────────────────────────────────────────────────

@app.route("/server/<name>/settings", methods=["POST"])
@login_required
def save_settings(name):
    data = load_data(); cfg = data["servers"].get(name)
    if not cfg: return jsonify({"success": False, "error": "Not found"}), 404
    payload = request.get_json()
    cfg["main_file"]             = payload.get("main_file", cfg.get("main_file", ""))
    cfg["port"]                  = payload.get("port", cfg.get("port", 8080))
    cfg["auto_restart"]          = payload.get("auto_restart", cfg.get("auto_restart", False))
    cfg["auto_restart_interval"] = int(payload.get("auto_restart_interval", cfg.get("auto_restart_interval", 3600)))
    data["servers"][name] = cfg; save_data(data)
    if cfg["auto_restart"] and cfg.get("status") == "running":
        _schedule_auto_restart(name)
    elif not cfg["auto_restart"] and name in AUTO_RESTART_TIMERS:
        AUTO_RESTART_TIMERS[name].cancel(); del AUTO_RESTART_TIMERS[name]
    return jsonify({"success": True})


# ─── Start / Stop ─────────────────────────────────────────────────────────────

@app.route("/server/<name>/start", methods=["POST"])
@login_required
def start_server(name):
    data = load_data(); cfg = data["servers"].get(name)
    if not cfg: return jsonify({"success": False, "error": "Not found"}), 404
    pid = cfg.get("pid")
    if pid and is_process_alive(pid): return jsonify({"success": False, "error": "Already running"})
    main_file   = cfg.get("main_file") or "main.py"
    extract_dir = SERVERS_DIR / name / "extracted"
    if not (extract_dir / main_file).exists():
        return jsonify({"success": False, "error": f"{main_file} not found. Upload files first."})
    log_path = SERVERS_DIR / name / "logs.txt"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = get_run_command(cfg.get("runtime", "python"), main_file)
    env = os.environ.copy(); env["PORT"] = str(cfg.get("port", 8080))
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

@app.route("/server/<name>/stop", methods=["POST"])
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
    log_path = SERVERS_DIR / name / "logs.txt"
    try:
        with open(log_path, "a") as lf:
            lf.write(f"[{datetime.now().isoformat()}] Server stopped\n")
    except: pass
    cfg["status"] = "stopped"; cfg["pid"] = None
    data["servers"][name] = cfg; save_data(data)
    return jsonify({"success": True})


# ─── Logs ─────────────────────────────────────────────────────────────────────

@app.route("/server/<name>/logs")
@login_required
def get_logs(name):
    log_path = SERVERS_DIR / name / "logs.txt"
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

@app.route("/server/<name>/logs/clear", methods=["POST"])
@login_required
def clear_logs(name):
    try: (SERVERS_DIR / name / "logs.txt").write_text("")
    except: pass
    return jsonify({"success": True})


# ─── Admin routes (secret path) ───────────────────────────────────────────────

def _admin_routes(app):
    ap = ADMIN_PATH   # e.g. "Sulav"

    @app.route(f"/{ap}/login", methods=["GET", "POST"])
    def admin_login():
        if request.method == "POST":
            pw = request.form.get("password", "")
            if pw == ADMIN_PASSWORD:
                session["admin"] = True
                return redirect(f"/{ap}/panel")
            return render_template("admin_login.html", error="Wrong admin password")
        return render_template("admin_login.html", error=None)

    @app.route(f"/{ap}/logout")
    def admin_logout():
        session.pop("admin", None); return redirect(url_for("login"))

    @app.route(f"/{ap}/panel")
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
                               total_files=total_files)

    @app.route(f"/{ap}/user/<username>/files")
    @admin_required
    def admin_user_files(username):
        data = load_data()
        user_servers = {k: v for k, v in data["servers"].items() if v.get("owner") == username}
        file_data = {n: {"config": c, "files": list_files(SERVERS_DIR / n / "extracted")}
                     for n, c in user_servers.items()}
        return render_template("admin_files.html", username=username, file_data=file_data)

    @app.route(f"/{ap}/user/<username>/delete", methods=["POST"])
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

    @app.route(f"/{ap}/maintenance", methods=["POST"])
    @admin_required
    def toggle_maintenance():
        data = load_data(); payload = request.get_json()
        data["settings"]["maintenance"]     = payload.get("enabled", False)
        data["settings"]["maintenance_msg"] = payload.get("message", "Under maintenance")
        save_data(data); return jsonify({"success": True})

    @app.route(f"/{ap}/theme", methods=["POST"])
    @admin_required
    def save_theme():
        data = load_data(); payload = request.get_json()
        data["settings"]["accent_color"] = payload.get("color", "#00ff41")
        save_data(data); return jsonify({"success": True})

    @app.route(f"/{ap}/broadcast", methods=["POST"])
    @admin_required
    def save_broadcast():
        data = load_data(); payload = request.get_json()
        data["settings"]["broadcast"] = {
            "active":  payload.get("active", False),
            "message": payload.get("message", ""),
            "btype":   payload.get("btype", "info")
        }
        save_data(data); return jsonify({"success": True})

    @app.route(f"/{ap}/file/<project_name>/download")
    @admin_required
    def admin_download_file(project_name):
        file_path = request.args.get("path", "")
        if not file_path: abort(400)
        safe_path = (SERVERS_DIR / project_name / "extracted" / file_path).resolve()
        base      = (SERVERS_DIR / project_name / "extracted").resolve()
        if not str(safe_path).startswith(str(base)) or not safe_path.exists() or safe_path.is_dir():
            abort(404)
        return send_file(safe_path, as_attachment=True, download_name=safe_path.name)

    @app.route(f"/{ap}/project/<project_name>/download")
    @admin_required
    def admin_download_project(project_name):
        type_filter = request.args.get("type", "all")
        extract_dir = SERVERS_DIR / project_name / "extracted"
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

    @app.route(f"/{ap}/user/<username>/download")
    @admin_required
    def admin_download_user(username):
        type_filter  = request.args.get("type", "all")
        data         = load_data()
        user_servers = {k: v for k, v in data["servers"].items() if v.get("owner") == username}
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name in user_servers:
                extract_dir = SERVERS_DIR / name / "extracted"
                if not extract_dir.exists(): continue
                for f in extract_dir.rglob("*"):
                    if f.is_file() and (type_filter == "all" or f.name.endswith(type_filter)):
                        zf.write(f, Path(name) / f.relative_to(extract_dir))
        buf.seek(0)
        ext_part = type_filter.replace(".", "") if type_filter != "all" else ""
        fname = f"{username}-files{'-' + ext_part if ext_part else ''}.zip"
        return send_file(buf, as_attachment=True, download_name=fname, mimetype="application/zip")

_admin_routes(app)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
