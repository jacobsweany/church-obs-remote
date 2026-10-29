#!/usr/bin/env python3
"""Church media dashboard — single file, Python stdlib only.

Runs on an offsite Mac, fronted by a cloudflared tunnel (any host).
One control surface for:
  - Service: one-tap Start / Stop sequence (OBS + Zoom + camera)
  - Camera:  PTZOptics F31 HTTP API (pan/tilt/zoom, presets, home, live stream)
  - OBS:     OBS-WebSocket v5 (scenes, record, virtual camera)
  - Zoom:    join / scripted sign-in (creds in Keychain) / leave

Security model:
  - Binds 127.0.0.1 only; cloudflared is the only route in.
  - Every /api/* and /setup request needs Authorization: Bearer <token>.
  - Zoom password is stored ONLY in the macOS Keychain (security CLI), never
    in config or on disk.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import struct
import subprocess
import os
import sys
import signal
import threading
import time
from datetime import datetime, timedelta
import urllib.error
import urllib.parse
import urllib.request
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOME = os.path.expanduser("~/church")
CONFIG_PATH = os.path.join(HOME, "config.json")
LOG_PATH = os.path.join(HOME, "dash.log")

def log(*a):
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + " ".join(str(x) for x in a)
    try:
        with open(LOG_PATH, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass

def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)

def save_config(c):
    with open(CONFIG_PATH, "w") as f:
        json.dump(c, f, indent=2)
    os.chmod(CONFIG_PATH, 0o600)

CFG = load_config()
PORT = int(CFG.get("port", 8080))

def _all_tokens():
    """Every valid token value: the legacy admin token + per-profile tokens."""
    out = []
    t = CFG.get("token")
    if t:
        out.append(t)
    for entry in (CFG.get("tokens") or {}).values():
        t = entry.get("token")
        if t:
            out.append(t)
    return out

def _token_match(cand):
    """Constant-time check against ANY known token (admin or per-profile).
    Bytes compare so non-ASCII input can't raise TypeError."""
    if not cand:
        return False
    c = cand.encode("utf-8", "replace")
    for t in _all_tokens():
        try:
            if hmac.compare_digest(c, t.encode("utf-8", "replace")):
                return True
        except Exception:
            continue
    return False

def _token_entry(tok):
    """Map a matched token value to its config entry (or the admin entry)."""
    if not tok:
        return None
    for entry in (CFG.get("tokens") or {}).values():
        if entry.get("token") == tok:
            return entry
    if CFG.get("token") and tok == CFG["token"]:
        return {"admin": True, "name": "Admin"}
    return {"admin": True, "name": "Admin"}

# --- session tracking (who used the dashboard, when, and from where) ---
_SESSIONS = {}  # token -> record: name/admin/first/last/visits/visit_start/active_seconds/browser/os/device
_SESSIONS_LOCK = threading.Lock()
SESSION_ACTIVE_TTL = 30.0   # activity within this window => "currently connected"
SESSION_GAP = 60.0          # inactivity longer than this => next visit is a new one
SESSION_FILE = os.path.join(HOME, "sessions.json")
_SESSIONS_SAVE_AT = [0.0]

def _parse_ua(ua):
    """Lightweight User-Agent parse (browser/os/device), no external deps."""
    out = {"browser": None, "os": None, "device": "desktop"}
    if not ua:
        return out
    if "iPhone" in ua:
        out["device"] = "mobile"
    elif "iPad" in ua:
        out["device"] = "tablet"
    elif "Android" in ua:
        out["device"] = "mobile" if "Mobile" in ua else "tablet"
    m = re.search(r"iPhone OS ([\d_]+)", ua)
    if m:
        out["os"] = "iOS " + m.group(1).replace("_", ".")
    elif "iPad" in ua:
        out["os"] = "iPadOS"
    else:
        m = re.search(r"Android ([\d.]+)", ua)
        if m:
            out["os"] = "Android " + m.group(1)
        elif "Windows NT 10" in ua:
            out["os"] = "Windows 10/11"
        elif "Windows NT" in ua:
            out["os"] = "Windows"
        elif "CrOS" in ua:
            out["os"] = "ChromeOS"
        elif "Mac OS X" in ua:
            m = re.search(r"Mac OS X ([\d_]+)", ua)
            out["os"] = "macOS " + m.group(1).replace("_", ".") if m else "macOS"
        elif "Linux" in ua:
            out["os"] = "Linux"
    if "Edg/" in ua:
        out["browser"] = "Edge"
    elif "OPR/" in ua:
        out["browser"] = "Opera"
    elif "FxiOS" in ua:
        out["browser"] = "Firefox (iOS)"
    elif "Firefox/" in ua:
        out["browser"] = "Firefox"
    elif "Chrome/" in ua:
        out["browser"] = "Chrome"
    elif "Safari/" in ua:
        out["browser"] = "Safari"
    return out

def _load_sessions():
    try:
        with open(SESSION_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for tok, rec in data.items():
                if isinstance(rec, dict) and rec.get("name"):
                    _SESSIONS[tok] = rec
    except Exception:
        pass

def _save_sessions():
    """Throttled persistence (<= once / 2s). File holds tokens => chmod 600."""
    now = time.time()
    if now - _SESSIONS_SAVE_AT[0] < 2.0:
        return
    _SESSIONS_SAVE_AT[0] = now
    try:
        with _SESSIONS_LOCK:
            snapshot = {t: dict(r) for t, r in _SESSIONS.items()}
        with open(SESSION_FILE, "w", encoding="utf-8") as f:
            json.dump(snapshot, f)
        os.chmod(SESSION_FILE, 0o600)
    except Exception:
        pass

def _today_str():
    return time.strftime("%Y-%m-%d")  # Mac local date

def _note_session(tok, ua=""):
    if not tok:
        return
    entry = _token_entry(tok) or {}
    now = time.time()
    day = _today_str()
    with _SESSIONS_LOCK:
        rec = _SESSIONS.get(tok)
        if rec is None:
            rec = _SESSIONS[tok] = {"name": entry.get("name") or "?",
                                    "admin": bool(entry.get("admin")),
                                    "first": now, "last": now,
                                    "visits": 1, "visit_start": now,
                                    "active_seconds": 0, "day": day,
                                    "browser": None, "os": None, "device": None}
        elif rec.get("day") != day:
            # Daily reset: fresh counters for the new day (keep identity +
            # last-seen browser details)
            rec["first"] = now
            rec["visits"] = 1
            rec["visit_start"] = now
            rec["active_seconds"] = 0
            rec["day"] = day
        elif now - rec.get("last", 0) > SESSION_GAP:
            rec["visits"] = rec.get("visits", 1) + 1
            rec["active_seconds"] = rec.get("active_seconds", 0) + max(
                0.0, rec.get("last", now) - rec.get("visit_start", rec.get("last", now)))
            rec["visit_start"] = now
        if ua:
            par = _parse_ua(ua)
            rec["browser"], rec["os"], rec["device"] = par["browser"], par["os"], par["device"]
        rec["last"] = now
    _save_sessions()

def _session_view(full=True, viewer_tok=None):
    """Account usage for the footer status.
    full (admin): all accounts, active first, with browser/os/visits/duration.
    lite (others): currently-active accounts only (names), excluding the viewer."""
    now = time.time()
    today = _today_str()
    with _SESSIONS_LOCK:
        out = []
        for tok, x in _SESSIONS.items():
            if x.get("admin"):
                continue
            if x.get("day") != today:
                continue  # daily reset: yesterday's usage is not shown today
            if viewer_tok and tok == viewer_tok:
                continue
            active = (now - x.get("last", 0)) <= SESSION_ACTIVE_TTL
            if not full and not active:
                continue
            base = {"name": x.get("name") or "?",
                    "active": active,
                    "seconds_ago": max(0, int(now - x.get("last", now)))}
            if full:
                dur = int(x.get("active_seconds", 0))
                if active:
                    dur += int(max(0.0, now - x.get("visit_start", now)))
                base.update({"visits": int(x.get("visits", 1)),
                             "active_seconds": dur,
                             "browser": x.get("browser"),
                             "os": x.get("os"),
                             "device": x.get("device")})
            out.append(base)
    out.sort(key=lambda r: (not r["active"], r["seconds_ago"]))
    return out[:10]

_load_sessions()

# ------------------------------------------------- profiles (multi-congregation)
_ACTIVE_PROFILE = None  # admin's currently selected profile (in-memory)
_PROFILE_LOCK = threading.Lock()
# Serialize every state-changing Zoom operation (user browser + scheduler +
# tests can all hit these concurrently; interleaved AX/menu ops corrupt each
# other). Read-only ops (attendees) also take it briefly.
_ZOOM_OP_LOCK = threading.RLock()  # reentrant: signout nests into leave/logout

# --- live operation progress (UI polls /api/operation while an action runs) ---
_OP = {"op": None, "step": None, "updated": 0, "done": False, "ok": None, "detail": None}
_OP_LOCK = threading.Lock()

def op_begin(name):
    with _OP_LOCK:
        _OP.update(op=name, step=None, updated=time.time(), done=False, ok=None, detail=None)

def op_step(text):
    with _OP_LOCK:
        _OP.update(step=str(text)[:200], updated=time.time())

def op_finish(ok, detail=""):
    with _OP_LOCK:
        _OP.update(done=True, ok=bool(ok), detail=str(detail)[:300], updated=time.time())

def _slug(name):
    """Stable keychain/id key from a congregation name."""
    return re.sub(r"[^a-z0-9]+", "-", str(name).lower()).strip("-")

_DOW = {"mon": 0, "tue": 1, "wed": 2, "thu": 3, "fri": 4, "sat": 5,
        "sun": 6, "monday": 0, "tuesday": 1, "wednesday": 2, "thursday": 3,
        "friday": 4, "saturday": 5, "sunday": 6}

def _parse_dow(v):
    s = str(v or "sun").strip().lower()
    if s in _DOW:
        return _DOW[s]
    try:
        n = int(s)
        if 0 <= n <= 6:
            return n
    except ValueError:
        pass
    return 6

_CSV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "congregations.csv")
_CSV_CACHE = {"mtime": None, "meetings": None}

def _load_meetings_csv():
    """Congregation data lives in congregations.csv (name-keyed). Passwords
    and tokens are NOT here (Keychain / config.json). Reloads when mtime
    changes, so editing the CSV takes effect on the next request."""
    try:
        mt = os.path.getmtime(_CSV_PATH)
    except OSError:
        return None
    if _CSV_CACHE["mtime"] == mt and _CSV_CACHE["meetings"] is not None:
        return _CSV_CACHE["meetings"]
    try:
        import csv as _csv
        rows = []
        with open(_CSV_PATH, newline="", encoding="utf-8") as f:
            for r in _csv.DictReader(f):
                name = (r.get("name") or "").strip()
                if not name:
                    continue
                hhmm = (r.get("time") or "").strip() or "09:00"
                dow_raw = (r.get("dow") or "").strip()
                # empty dow = ad-hoc account (no scheduled meeting); the
                # scheduler and schedule UI skip entries with weekly=None
                weekly = {"dow": _parse_dow(dow_raw), "time": hhmm} if dow_raw else None
                rows.append({
                    "id": _slug(name),
                    "name": name,
                    "email": (r.get("email") or "").strip(),
                    "confno": (r.get("confno") or "").strip(),
                    "weekly": weekly,
                    "scene": (r.get("scene") or "").strip() or None,
                    "zoom_account": name,
                })
        _CSV_CACHE.update(mtime=mt, meetings=rows)
        log("csv: loaded %d congregation(s) from %s" % (len(rows), _CSV_PATH))
    except Exception as e:
        log("csv: load error (keeping stale): %s" % e)
    return _CSV_CACHE["meetings"]

def _meetings():
    m = _load_meetings_csv()
    if m is not None:
        return m
    return CFG.get("meetings", [])

def _meeting(mid):
    """Look up a congregation by name, slug, or legacy id."""
    want = str(mid or "").strip()
    wl = want.lower()
    for m in _meetings():
        if want in (m.get("name"), m.get("id"), m.get("zoom_account")):
            return m
        if wl in (str(m.get("name", "")).lower(), str(m.get("id", "")).lower()):
            return m
    return None

def _default_profile_id():
    ms = _meetings()
    return ms[0]["id"] if ms else None

def _profile_for_entry(entry):
    """Resolve the profile id a request is scoped to."""
    if entry is None:
        return _default_profile_id()
    if entry.get("profile"):
        return entry["profile"]
    if entry.get("admin"):
        return _ACTIVE_PROFILE or _default_profile_id()
    return _default_profile_id()

# one-account-at-a-time tracking (survives within a dashboard run)
_LAST_ZOOM_ACCOUNT = None
_SVC_ACTIVE = False  # service sequence is up (set by svc_start / cleared by svc_stop)

def _set_last_zoom_account(aid):
    global _LAST_ZOOM_ACCOUNT
    _LAST_ZOOM_ACCOUNT = aid

# anti-lockout: after a FAILED sign-in for an account, refuse further
# attempts for that account for a while (Zoom locks accounts after repeated
# failures; a retry storm made it faster). Keyed per account slug.
_LAST_LOGIN_FAIL = {}  # slug -> timestamp of last failed attempt
_LOGIN_COOLDOWN_S = 600  # 10 min

def _login_cooldown_active(account_id):
    ts = _LAST_LOGIN_FAIL.get(_slug(account_id), 0)
    dt = time.time() - ts
    return dt < _LOGIN_COOLDOWN_S, int(_LOGIN_COOLDOWN_S - dt)

# ---------------------------------------------------------------- OBS-WS ----
class ObsClient:
    """Minimal OBS-WebSocket v5 client (RFC6455 + HMAC identify), stdlib only."""

    def __init__(self, host, port, password, ssl=False):
        self.host, self.port, self.password = host, port, password
        self.ssl = ssl
        self.lock = threading.RLock()
        self.sock = None
        self._rxbuf = b""
        self.challenge = None
        self.connected = False
        self.proto = None      # 57 = obs-websocket >=5.7 (op/d envelope), 50 = 5.0.x
        self._reqid = 0
        self._stop = threading.Event()
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while not self._stop.is_set():
            try:
                if self._connect():
                    log("obs: connected")
                    self._keepalive()
            except Exception as e:
                log("obs: drop:", e)
            finally:
                self.connected = False
                self._close()
            if self._stop.is_set():
                break
            time.sleep(3)

    def _close(self):
        with self.lock:
            if self.sock:
                try:
                    self.sock.close()
                except Exception:
                    pass
            self.sock = None
            self._rxbuf = b""
            self.proto = None

    def _connect(self):
        with self.lock:
            raw = socket.create_connection((self.host, self.port), timeout=8)
            if self.ssl:
                import ssl as _ssl
                ctx = _ssl.create_default_context()
                ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
                raw = ctx.wrap_socket(raw, server_hostname=self.host)
            key = base64.b64encode(os.urandom(16)).decode()
            req = ("GET /obs/ws HTTP/1.1\r\nHost: %s:%s\r\nUpgrade: websocket\r\n"
                   "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
                   "Sec-WebSocket-Version: 13\r\n\r\n" % (self.host, self.port, key))
            raw.sendall(req.encode())
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = raw.recv(4096)
                if not chunk:
                    raise RuntimeError("ws upgrade closed")
                buf += chunk
            head, _, rest = buf.partition(b"\r\n\r\n")
            if b"101" not in head.split(b"\r\n", 1)[0]:
                raise RuntimeError("ws upgrade failed: " + head[:120].decode(errors="replace"))
            self.sock = raw
            self._rxbuf = rest
            first = json.loads(self._recv_msg())
            fd = first.get("d")
            if isinstance(fd, dict) and "op" in first and "authentication" in fd:
                # obs-websocket >= 5.7: {"d": {...}, "op": N} envelope
                self.proto = 57
                auth = fd["authentication"]
                challenge = auth.get("challenge", "")
                salt = auth.get("salt", "")
                rpcv = fd.get("rpcVersion", 1)
                secret = base64.b64encode(hashlib.sha256(
                    (self.password + salt).encode()).digest()).decode()
                authstr = base64.b64encode(hashlib.sha256(
                    (secret + challenge).encode()).digest()).decode()
                self._send_msg(json.dumps({"op": 1, "d": {
                    "authentication": authstr, "clientName": "church-dash",
                    "rpcVersion": rpcv}}))
                ack = json.loads(self._recv_msg())
                if ack.get("op") != 2:
                    raise RuntimeError("obs identify rejected: %s" % json.dumps(ack)[:300])
            elif first.get("status") == "identifying":
                # obs-websocket 5.0.x legacy flow
                self.proto = 50
                self.challenge = first.get("challenge")
                self._send_msg(json.dumps({"auth": {"challenge": self.challenge,
                                                    "password": self._hmac(self.challenge)},
                                           "clientName": "church-dash", "rpcVersion": 1}))
                st = json.loads(self._recv_msg())
                if st.get("status") != "connected":
                    raise RuntimeError("obs identify failed: " + json.dumps(st)[:200])
            else:
                raise RuntimeError("obs: unrecognized first message: %s" % json.dumps(first)[:300])
            self.connected = True
            return True

    def _hmac(self, challenge):
        return hmac.new(self.password.encode(), challenge.encode(), hashlib.sha256).hexdigest()

    # -- framing --
    def _read_exact(self, n):
        while len(self._rxbuf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("obs ws closed")
            self._rxbuf += chunk
        out, self._rxbuf = self._rxbuf[:n], self._rxbuf[n:]
        return out

    def _recv_msg(self):
        msg = b""
        while True:
            b1, b2 = self._read_exact(2)
            fin = b1 & 0x80
            opcode = b1 & 0x0F
            masked = b2 & 0x80
            ln = b2 & 0x7F
            if ln == 126:
                ln = struct.unpack(">H", self._read_exact(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", self._read_exact(8))[0]
            mkey = self._read_exact(4) if masked else b""
            payload = self._read_exact(ln) if ln else b""
            if masked:
                payload = bytes(c ^ mkey[i % 4] for i, c in enumerate(payload))
            if opcode == 0x8:
                raise RuntimeError("obs closed the connection")
            if opcode == 0x9:
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            if opcode in (0x1, 0x2):
                msg += payload
            if fin:
                return msg.decode("utf-8", "replace")

    def _send_frame(self, opcode, payload):
        header = bytearray([0x80 | opcode])
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        key = os.urandom(4)
        header += key
        masked = bytes(c ^ key[i % 4] for i, c in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def _send_msg(self, text):
        self._send_frame(0x1, text.encode())

    def _keepalive(self):
        while self.sock and not self._stop.is_set():
            try:
                self._send_frame(0x9, b"ping")
            except Exception:
                return
            time.sleep(15)

    def rpc(self, name, params=None, timeout=10):
        with self.lock:
            if not (self.sock and self.connected):
                raise RuntimeError("obs not connected")
            try:
                self.sock.settimeout(timeout)
                if self.proto == 57:
                    self._reqid += 1
                    rid = self._reqid
                    self._send_msg(json.dumps({"op": 6, "d": {
                        "requestId": rid, "requestType": name,
                        "requestData": params or {}}}))
                    d = None
                    for _ in range(100):  # skip pushed events (op 4/5)
                        d = json.loads(self._recv_msg())
                        if d.get("op") in (4, 5):
                            continue
                        if (d.get("d") or {}).get("requestId") == rid:
                            break
                    dd = (d or {}).get("d") or {}
                    st = dd.get("requestStatus") or {}
                    if not st.get("result"):
                        raise RuntimeError("obs %s: %s" % (
                            name, st.get("comment") or json.dumps(st)[:160]))
                    return dd.get("responseData") or {}
                payload = {"auth": {"challenge": self.challenge, "password": self.password},
                           "request": {"name": name, "params": params or {}},
                           "rpcVersion": 1}
                self._send_msg(json.dumps(payload))
                d = json.loads(self._recv_msg())
            finally:
                self.sock.settimeout(None)
            resp = d.get("response")
            if not resp or resp.get("status") != "ok":
                raise RuntimeError("obs %s: %s" % (name, json.dumps(resp or d)[:200]))
            return resp.get("result", {})

OBS = None
if CFG.get("obs"):
    _o = CFG["obs"]
    OBS = ObsClient(_o["host"], int(_o.get("port", 4455)), _o["pass"], bool(_o.get("ssl", False)))

# ----------------------------------------------------------------- camera ---
class CameraClient:
    """PTZOptics F31 HTTP API with HTTP-digest auth."""

    def __init__(self, cfg):
        self.host = cfg["host"]
        self.port = int(cfg.get("port", 80))
        self.user = cfg.get("user")
        self.password = cfg.get("pass")

    def digest_header(self, method, uri, challenge):
        parts = {k: (v or w) for k, v, w in re.findall(r'(\w+)=(?:"([^"]*)"|([^\s,]+))', challenge or "")}
        realm = parts.get("realm", "")
        nonce = parts.get("nonce", "")
        qop = parts.get("qop", "")
        ha1 = hashlib.md5(("%s:%s:%s" % (self.user, realm, self.password)).encode()).hexdigest()
        ha2 = hashlib.md5(("%s:%s" % (method, uri)).encode()).hexdigest()
        if "auth" in qop:
            cnonce = secrets.token_hex(8)
            resp = hashlib.md5(("%s:%s:00000001:%s:auth:%s" % (ha1, nonce, cnonce, ha2)).encode()).hexdigest()
            return ('Digest username="%s", realm="%s", nonce="%s", uri="%s", '
                    'qop=auth, nc=00000001, cnonce="%s", response="%s"'
                    % (self.user, realm, nonce, uri, cnonce, resp))
        resp = hashlib.md5(("%s:%s:%s" % (ha1, nonce, ha2)).encode()).hexdigest()
        return ('Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"'
                % (self.user, realm, nonce, uri, resp))

    def _base_curl(self):
        cmd = ["curl", "-s"]
        if self.user:
            cmd += ["--user", "%s:%s" % (self.user, self.password)]
        return cmd

    def get(self, path, timeout=8):
        """GET via curl. (Python sockets to this host are blocked on this Mac -
        'No route to host' - but curl connects fine, so use it for all camera I/O.)
        curl handles HTTP digest auth natively. Returns (status, body, headers)."""
        url = "http://%s:%s%s" % (self.host, self.port, path)
        cmd = self._base_curl() + ["--max-time", str(timeout),
                                   "-w", "\n%{http_code}", url]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=timeout + 5)
        except subprocess.TimeoutExpired:
            raise RuntimeError("camera request timed out")
        out = r.stdout
        idx = out.rfind(b"\n")
        if idx >= 0:
            body = out[:idx]
            try:
                code = int(out[idx + 1:].decode().strip() or 0)
            except ValueError:
                code = 0
        else:
            body, code = out, 0
        if r.returncode not in (0, 28) and code == 0:
            raise RuntimeError("curl rc=%s: %s" % (r.returncode,
                           (r.stderr or b"").decode(errors="replace")[:100]))
        return (code, body, {})

    def stream_proc(self, path):
        """Start curl streaming an MJPEG endpoint; stdout is the byte stream."""
        url = "http://%s:%s%s" % (self.host, self.port, path)
        cmd = self._base_curl() + ["--no-buffer", "-N", url]
        return subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)

    def cmd(self, *parts, timeout=8):
        """ptzctrl command, e.g. cmd("ptzcmd", "poscall", "1")."""
        path = "/cgi-bin/ptzctrl.cgi?" + "&".join(str(p) for p in parts)
        try:
            status, body, _ = self.get(path, timeout=timeout)
            try:
                data = json.loads(body)
            except Exception:
                data = {"raw": body[:200].decode(errors="replace")}
            return {"ok": status == 200, "status": status, "result": data}
        except Exception as e:
            return {"ok": False, "error": str(e)[:200]}

    def reachable(self, timeout=4):
        try:
            self.get("/", timeout=timeout)
            return True, None  # answered (200 or 401 = auth wall, still alive)
        except Exception as e:
            return False, str(e)[:120]

CAM = CameraClient(CFG["camera"]) if CFG.get("camera") else None
STREAM_TARGET = None  # (host, port, uri) once probed

def probe_stream():
    global STREAM_TARGET
    cands = ["/mjpg/video.mjpg", "/video.mjpg", "/live.mjpg",
             "/stream/video.mjpg", "/cgi-bin/snapshot.cgi", "/snapshot"]
    for uri in cands:
        url = "http://%s:%s%s" % (CAM.host, CAM.port, uri)
        cmd = CAM._base_curl() + ["--max-time", "4", "-o", "/dev/null",
                                  "-w", "%{http_code} %{content_type}", url]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=10)
            out = (r.stdout or b"").decode(errors="replace").strip()
            code, _, ct = out.partition(" ")
            if code == "200" and ("multipart" in ct.lower() or "image" in ct.lower()):
                STREAM_TARGET = (CAM.host, CAM.port, uri)
                log("stream probe found:", uri)
                return
        except Exception:
            continue
    log("stream probe: no live stream endpoint found")

threading.Thread(target=probe_stream, daemon=True).start()

# ------------------------------------------------------------------- zoom ---
def zoom_running():
    try:
        return subprocess.run(["pgrep", "-x", "zoom.us"],
                              capture_output=True, timeout=5).returncode == 0
    except Exception:
        return False

def obs_running():
    try:
        return subprocess.run(["pgrep", "-x", "OBS"],
                              capture_output=True, timeout=5).returncode == 0
    except Exception:
        return False

def _kc(acct):
    """Read a Keychain value (service church-dash), or None."""
    r = subprocess.run(["security", "find-generic-password", "-s", "church-dash",
                        "-a", acct, "-w"], capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        return None
    v = r.stdout.strip()
    return v or None

def zoom_setup(user, password, account_id):
    key = _slug(account_id)
    for acct, val in (("zoom-user-%s" % key, user),
                      ("zoom-pass-%s" % key, password)):
        r = subprocess.run(["security", "add-generic-password", "-U",
                            "-s", "church-dash", "-a", acct, "-w", val],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            raise RuntimeError("keychain write failed: %s" % (r.stderr.strip()[:120]))
    log("zoom: credentials stored in Keychain for account %s (key %s)" % (account_id, key))

# --- real mouse click helper (CGEvent) -------------------------------------
ZOOM_CLICK_PY_SRC = r'''#!/usr/bin/env python3
"""Real mouse click via CoreGraphics (works where AX clicks don't)."""
import sys, time
import ctypes

class CGPoint(ctypes.Structure):
    _fields_ = [("x", ctypes.c_double), ("y", ctypes.c_double)]

cg = ctypes.cdll.LoadLibrary("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
cg.CGEventCreateMouseEvent.restype = ctypes.c_void_p
cg.CGEventCreateMouseEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint32, CGPoint, ctypes.c_uint32]
cg.CGEventPost.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
cg.CFRelease.argtypes = [ctypes.c_void_p]

def click(x, y):
    p = CGPoint(float(x), float(y))
    down = cg.CGEventCreateMouseEvent(None, 1, p, 0)  # kCGEventLeftMouseDown
    up = cg.CGEventCreateMouseEvent(None, 2, p, 0)    # kCGEventLeftMouseUp
    cg.CGEventPost(0, down)                           # kCGHIDEventTap
    time.sleep(0.06)
    cg.CGEventPost(0, up)
    cg.CFRelease(down); cg.CFRelease(up)

if __name__ == "__main__":
    click(float(sys.argv[1]), float(sys.argv[2]))
    print("clicked %s %s" % (sys.argv[1], sys.argv[2]))
'''

def zoom_mouse_click(x, y):
    """Post a real left-click at (x, y) in screen points (GUI session required)."""
    script = os.path.expanduser("~/church/zoom_click.py")
    if not os.path.exists(script):
        try:
            os.makedirs(os.path.dirname(script), exist_ok=True)
            with open(script, "w") as f:
                f.write(ZOOM_CLICK_PY_SRC)
        except Exception:
            pass
    try:
        r = subprocess.run(["python3", script, str(x), str(y)],
                           capture_output=True, text=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return False

def zoom_window_rect():
    """Front Zoom window (x, y, w, h) in points, or None."""
    def osa(e):
        r = subprocess.run(["osascript", "-e", e], capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    try:
        pos = osa('tell application "System Events" to get position of window 1 of process "zoom.us"').replace(" ", "")
        sz = osa('tell application "System Events" to get size of window 1 of process "zoom.us"').replace(" ", "")
        px, py = (int(v) for v in pos.split(","))
        w, h = (int(v) for v in sz.split(","))
        return px, py, w, h
    except Exception:
        return None

def _zoom_keystroke_flow(account_id):
    """Keyboard sign-in for the Zoom Workplace login screen (email field +
    'Next' button). The email field is AUTO-FOCUSED on load (verified 2026-10-21
    from a screen capture: blue focus ring + cursor).

    CRITICAL: do NOT click to focus. The old flow clicked (0.40w, 0.53h)
    which sits on the 'Next' button - with a pre-filled email that click
    SUBMITS the form to the password screen, and the email typing is then
    lost (observed: quartz email + wrong password = failed login).
    Sequence: Cmd+A (select any pre-fill) -> type email -> Enter -> type
    password -> Enter. One submission only."""
    key = _slug(account_id)
    script = (r'''
on run
  tell application "zoom.us" to activate
  delay 1.2
  tell application "System Events"
    tell process "zoom.us"
      set frontmost to true
    end tell
    delay 0.3
    key code 53
    delay 0.3
    keystroke "a" using command down
    delay 0.3
    set theUser to do shell script "security find-generic-password -s church-dash -a zoom-user-__ACCT__ -w"
    keystroke theUser
    delay 0.8
    key code 36
    delay 2
    set thePass to do shell script "security find-generic-password -s church-dash -a zoom-pass-__ACCT__ -w"
    keystroke thePass
    delay 0.7
    key code 36
  end tell
  return "flow executed"
end run
''').replace("__ACCT__", key)
    r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=90)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip()[:300])

def _zoom_type_password(account_id):
    script = (r'''
tell application "zoom.us" to activate
delay 0.4
tell application "System Events"
  set thePass to do shell script "security find-generic-password -s church-dash -a zoom-pass-__ACCT__ -w"
  keystroke thePass
  delay 0.5
  key code 36
end tell
''').replace("__ACCT__", _slug(account_id))
    r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip()[:200])

def _zoom_wait_signed_in(max_s=6, step=0.5):
    """Signed-in = app still running AND no Login window.
    (If the app quits mid-attempt that is a FAILURE, not a success -
    this used to report false positives when Zoom closed itself.)"""
    t0 = time.time()
    while time.time() - t0 < max_s:
        if not zoom_running():
            return False
        if not zoom_on_signin():
            return True
        time.sleep(step)
    return zoom_running() and not zoom_on_signin()

def _zoom_card_click():
    rect = zoom_window_rect()
    if not rect:
        raise RuntimeError("cannot locate Zoom window to click the account card")
    px, py, w, h = rect
    if not zoom_mouse_click(int(px + 0.40 * w), int(py + 0.53 * h)):
        raise RuntimeError("account-card click failed (needs GUI-context permissions)")
    log("zoom: clicked account card at %d,%d" % (px + 0.40 * w, py + 0.53 * h))

def _zoom_ensure_signed_out():
    """Ensure the app is running AND signed out (on the Login screen).
    CRITICAL: never quit the app here - if a session is active and the app is
    quit, Zoom AUTO-REAUTHENTICATES the cached account on the next launch,
    which silently blocks logging in a different account (observed 2026-10-19).
    Sign out via menu, then log in the new account in the same app session."""
    if not zoom_running():
        subprocess.run(["open", "-a", "zoom.us"], check=False)
        for _ in range(30):
            time.sleep(0.5)
            if zoom_running():
                break
        time.sleep(3)  # settle; Zoom may auto-reauth a cached session here
    if not zoom_on_signin():
        try:
            lo = zoom_logout()
            log("zoom: pre-login sign-out: %s" % lo.get("detail"))
        except Exception as e:
            log("zoom: pre-login sign-out error: %s" % e)
    for _ in range(10):
        if zoom_on_signin():
            return True
        time.sleep(1)
    ok = zoom_on_signin()
    log("zoom: ensure-signed-out -> %s" % ("Login screen" if ok else "NOT on Login screen"))
    return ok

def _zoom_launch_and_wait(max_s=15):
    """Launch Zoom if needed and wait for the process + a moment for windows."""
    if not zoom_running():
        subprocess.run(["open", "-a", "zoom.us"], check=False)
        for _ in range(30):
            time.sleep(0.5)
            if zoom_running():
                break
        time.sleep(2)

def zoom_login_flow(account_id, variant=None):
    with _ZOOM_OP_LOCK:
        return _zoom_login_flow_impl(account_id, variant)

def _zoom_login_flow_impl(account_id, variant=None):
    op_begin("zoom sign-in (%s)" % account_id)
    try:
        r = _zoom_login_flow_core(account_id, variant)
    except Exception as e:
        op_finish(False, str(e)[:200])
        raise
    op_finish(bool(r.get("ok")), r.get("detail", ""))
    return r

def _zoom_login_flow_core(account_id, variant=None):
    """Sign in as a saved account (Keychain: zoom-user-<id>/zoom-pass-<id>),
    handling BOTH Zoom login variants, fast:
      A) blank email field -> keyboard: email, Enter, password, Enter
      B) "previously signed in" account card -> real mouse click on the
         card (window-relative ~0.40w, 0.53h) -> password, Enter.
    The keyboard flow is harmless on B (absorbed), so we try it first with
    short waits, then fall straight through to the card click."""
    _key = _slug(account_id)
    if not (_kc("zoom-user-%s" % _key) and _kc("zoom-pass-%s" % _key)):
        return {"ok": False, "detail": "Zoom credentials for '%s' not in Keychain yet (save once via 'Set Zoom credentials')" % account_id}
    # One account at a time. Unless THIS dashboard run already signed in the
    # requested account, a different (or unknown) session may be cached — and
    # Zoom AUTO-REAUTHENTICATES the cached account on launch, so a "successful"
    # keyboard login could actually be the WRONG account. Therefore: whenever
    # the account differs, do a deterministic reset (launch -> sign out of ALL
    # accounts -> quit) BEFORE the login flow. Same-account fast path (e.g.
    # Stop then Start) is preserved: the cached session IS the wanted one.
    # anti-lockout gate: after a failed sign-in, don't hammer it again
    active, remaining = _login_cooldown_active(account_id)
    if active:
        return {"ok": False, "detail": ("cooldown: last sign-in failed and Zoom may have locked the account "
                                        "(it locks after repeated failures). Wait ~%d min, confirm the lock "
                                        "message is gone on the Mac screen, then retry." % max(1, remaining // 60))}
    if _LAST_ZOOM_ACCOUNT != account_id:
        log("zoom: switching to %s (previous: %s) - ensuring signed out first"
            % (account_id, _LAST_ZOOM_ACCOUNT or "unknown"))
        op_step("Switching accounts - signing out previous session…")
        # In a meeting? Leave first - the sign-out menu item is unreachable
        # from the in-meeting UI, and proceeding with the app in a meeting
        # once produced a FALSE 'signed in' (the old session was still up).
        # Quit ends the meeting; the subsequent ensure-signed-out does the
        # normal sign-out-via-menu in the fresh session.
        try:
            if "Zoom Webinar" in _zoom_window_names():
                log("zoom: in a meeting - leaving (quit) before account switch")
                zoom_leave()
        except Exception as e:
            log("zoom: leave-before-switch error: %s" % e)
        try:
            if not _zoom_ensure_signed_out():
                # HARD STOP: never type credentials into an unknown screen.
                return {"ok": False, "detail": ("could not reach the Zoom Login screen (a meeting may be in "
                                                "progress or Zoom is in an unexpected state). Check the Mac "
                                                "screen, leave the meeting / sign out there, then retry.")}
        except Exception as e:
            return {"ok": False, "detail": "pre-login sign-out failed: %s" % e}
    else:
        # same account as last login: app may be up (signed in or on Login) or
        # closed (auto-reauth on launch is the FAST path for the right account)
        op_step("Launching Zoom…")
        _zoom_launch_and_wait()
    # ONE sign-in attempt (click email field, clear any pre-fill, type creds).
    # No retry cascade - repeated failures lock the account.
    op_step("Signing in as %s…" % (_kc("zoom-user-%s" % _slug(account_id)) or account_id))
    try:
        _zoom_robust_signin(account_id)
    except Exception as e:
        log("zoom: sign-in flow error: %s" % e)
    op_step("Verifying signed-in state…")
    if _zoom_wait_signed_in(max_s=6):
        _LAST_LOGIN_FAIL.pop(_slug(account_id), None)
        return {"ok": True, "detail": "signed in %s" % account_id}
    # failed - record it and STOP (no more submissions until the cooldown ends)
    _LAST_LOGIN_FAIL[_slug(account_id)] = time.time()
    log("zoom: SIGN-IN FAILED for %s - cooldown started (no further attempts for %ds)"
        % (account_id, _LOGIN_COOLDOWN_S))
    return {"ok": False, "detail": ("sign-in did not complete. If the Mac screen shows "
                                    "'locked due to multiple failed sign in attempts', wait for Zoom to "
                                    "unlock (typically 30-60 min) and try again. The email field should "
                                    "show %s before pressing Sign in." % (_kc("zoom-user-%s" % _slug(account_id)) or "the account email"))}

def _zoom_click_rel(rx, ry):
    """Click at window-relative fractions (rx, ry) of the front Zoom window."""
    rect = zoom_window_rect()
    if not rect:
        raise RuntimeError("no Zoom window rect")
    px, py, w, h = rect
    if not zoom_mouse_click(px + rx * w, py + ry * h):
        raise RuntimeError("click at (%.2f, %.2f) failed" % (rx, ry))

def _zoom_stage_email(account_id):
    """Email-entry stage: Escape, select-all (clears any pre-fill), type the
    account's email, Enter. On the email-entry screen this advances to the
    password screen. On the cached-account CARD screen the keystrokes are
    absorbed by the inert pre-sign-in AI chat box - nothing submits (verified
    2026-10-21: keyboard flows on the card screen left it unchanged)."""
    key = _slug(account_id)
    script = (r'''
on run
  tell application "zoom.us" to activate
  delay 0.8
  tell application "System Events"
    key code 53
    delay 0.3
    keystroke "a" using command down
    delay 0.4
    set theUser to do shell script "security find-generic-password -s church-dash -a zoom-user-__ACCT__ -w"
    keystroke theUser
    delay 0.8
    key code 36
  end tell
  return "email stage done"
end run
''').replace("__ACCT__", key)
    r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip()[:300])

def _zoom_robust_signin(account_id):
    """Sign in that works on BOTH login screens without knowing which is
    showing (the AX tree is opaque - the dashboard cannot read the screen):
      1) email stage    -> email-entry screen: now on the password screen
      2) password stage -> completes the email-screen path
      3) if STILL on the Login window: we were on the cached-account CARD
         screen (stages 1-2 were absorbed harmlessly) -> click 'Sign into a
         different account' (0.45w, 0.61h) -> email-entry screen -> repeat.
    A password is never typed on the card screen and the card is never
    clicked, so a wrong password can never be submitted for a different
    account (no lockout risk)."""
    op_step("Entering email…")
    _zoom_stage_email(account_id)
    time.sleep(2.5)
    if not zoom_on_signin():
        return  # password screen already reached -> let caller wait
    op_step("Entering password…")
    _zoom_type_password(account_id)
    time.sleep(1.0)
    if _zoom_wait_signed_in(max_s=6):
        return
    log("zoom: still on Login screen - assuming cached-account card screen, clicking 'Sign into a different account'")
    op_step("Card screen - switching to the account sign-in form…")
    _zoom_click_rel(0.45, 0.61)
    time.sleep(2.5)
    op_step("Entering email…")
    _zoom_stage_email(account_id)
    time.sleep(2.5)
    op_step("Entering password…")
    _zoom_type_password(account_id)

def zoom_has_window():
    try:
        r = subprocess.run(["osascript", "-e",
                           'tell application "System Events" to return exists (window 1 of (first process whose name is "zoom.us"))'],
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip().startswith("true")
    except Exception:
        return False

def zoom_on_signin():
    """True if the front Zoom window is still the sign-in screen (title 'Login')."""
    script = r'''
tell application "System Events"
  if (exists (first process whose name is "zoom.us")) then
    tell process "zoom.us"
      try
        repeat with w in windows
          if (name of w) is "Login" then
            return true
          end if
        end repeat
      end try
    end tell
  end if
  return false
end tell
'''
    try:
        r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            log("zoom_on_signin script error: %s" % (r.stderr or r.stdout).strip()[:150])
            return False
        return r.stdout.strip().startswith("true")
    except Exception as e:
        log("zoom_on_signin error: %s" % e)
        return False

def zoom_join(confno, account_id, auto_login=True):
    url = "zoommtg://zoom.us/join?action=join&confno=%s" % confno
    if not zoom_running():
        subprocess.run(["open", "-a", "zoom.us"], check=False)
    # wait for a window to appear (fresh launch can take a few seconds)
    for _ in range(20):
        if zoom_has_window():
            break
        time.sleep(1)
    if zoom_on_signin():
        if not auto_login:
            return {"ok": False, "detail": "Zoom is on the sign-in screen; login not attempted"}
        r = zoom_login_flow(account_id)
        if not r["ok"]:
            return {"ok": False, "detail": "login flow failed: " + r["detail"]}
        for _ in range(10):
            if not zoom_on_signin():
                break
            time.sleep(1)
        if zoom_on_signin():
            return {"ok": False, "detail": "login flow ran but still on sign-in screen (check CAPTCHA/2FA)"}
    subprocess.run(["open", url], check=False)
    # Joining while connected to a stale/still-running meeting produces a
    # 'Join new meeting? ... Leave & Join' confirmation dialog (observed
    # 2026-10-20: host meetings keep running server-side after a forced quit,
    # and the next join URL prompts). The affirmative button is the RIGHT one
    # (highlighted) - accept it if it appears; otherwise wait for the
    # webinar window.
    for _ in range(15):
        if "Zoom Webinar" in _zoom_window_names():
            break
        try:
            if _zoom_accept_signout_dialog():
                log("zoom: join confirmation dialog accepted (clicked right button)")
        except Exception as e:
            log("zoom: join dialog accept error: %s" % e)
        time.sleep(1)
    in_wb = "Zoom Webinar" in _zoom_window_names()
    return {"ok": True, "detail": "join %s: %s" % (confno, "in webinar" if in_wb else "triggered (no webinar window yet)")}

def _zoom_quit_hard():
    """Quit the Zoom app (graceful first, then force)."""
    try:
        subprocess.run(["osascript", "-e", 'tell application "zoom.us" to quit'], check=False, timeout=15)
    except subprocess.TimeoutExpired:
        pass
    time.sleep(3)
    if zoom_running():
        subprocess.run(["pkill", "-x", "zoom.us"], check=False)
        time.sleep(1)


def zoom_full_close():
    """ONE-STOP CLOSE: end any active meeting/webinar, sign out completely,
    then close the Zoom client. No half-logged-in state survives.

    Order matters: the app is quit only AFTER the sign-out is confirmed
    (Login screen), because quitting with a live session makes Zoom
    auto-reauthenticate the cached account on next launch. If an active
    meeting blocks the sign-out, the quit ends the meeting and the sign-out
    is retried once in the fresh session."""
    with _ZOOM_OP_LOCK:
        global _LAST_ZOOM_ACCOUNT
        op_begin("zoom close")
        if not zoom_running():
            _LAST_ZOOM_ACCOUNT = None
            op_finish(True, "zoom not running; nothing to close")
            return {"ok": True, "detail": "zoom not running; nothing to close"}
        steps = []
        op_step("Signing out of all accounts…")
        lo = zoom_logout()
        steps.append("sign-out: " + (lo.get("detail") or ""))
        if not zoom_on_signin():
            in_meeting = "Zoom Webinar" in _zoom_window_names()
            log("zoom: full-close: sign-out unconfirmed%s - quitting to end it"
                % (" while in meeting" if in_meeting else ""))
            steps.append("meeting ended (quit)" if in_meeting else "sign-out unconfirmed; quitting")
            op_step("Quitting Zoom to end any meeting…")
            _zoom_quit_hard()
            if not zoom_running():
                subprocess.run(["open", "-a", "zoom.us"], check=False)
                for _ in range(24):
                    if zoom_running():
                        break
                    time.sleep(0.5)
                time.sleep(3)
            lo = zoom_logout()
            steps.append("sign-out 2: " + (lo.get("detail") or ""))
        op_step("Closing Zoom…")
        _zoom_quit_hard()
        time.sleep(3)
        closed = not zoom_running()
        _LAST_ZOOM_ACCOUNT = None
        steps.append("zoom closed" if closed else "zoom still running")
        op_finish(closed, "; ".join(steps))
        return {"ok": closed, "detail": "; ".join(steps)}


def zoom_leave(force=False):
    """Quit the app (leave = quit, since Electron doesn't expose its buttons).
    PREFER zoom_full_close() for a clean teardown (sign-out first)."""
    with _ZOOM_OP_LOCK:
        _zoom_quit_hard()
        ok = not zoom_running()
    return {"ok": ok, "detail": "zoom quit (session ended)" if ok else "zoom quit (force-killed)"}

def _zoom_accept_signout_dialog():
    """Zoom (2026-10-20) shows a 'Sign out of all accounts' CONFIRMATION dialog
    after the menu click: Cancel / Sign out, with Sign out as the RIGHT button
    (highlighted). An AppleScript Enter does not land on it (focus goes
    elsewhere); a bare CGEvent click is ignored by Chromium until a
    mouse-moved event sets the hovered element (zoom_click.py does that).
    NOTE: 'position as text' yields unseparated digits ("1058364") that can't
    be parsed unambiguously - so the button center is computed IN AppleScript
    and returned as "x,y".
    Returns True if a dialog button was clicked."""
    script = r"""
tell application "System Events"
  tell process "zoom.us"
    set bestcx to 0
    set bestcy to 0
    set bestx to -1
    repeat with w in (windows)
      try
        if (name of w) is missing value then
          repeat with b in (buttons of w)
            set p to (position of b)
            set x to item 1 of p
            if x > bestx then
              set bestx to x
              set s to (size of b)
              set bestcx to (item 1 of p) + ((item 1 of s) / 2)
              set bestcy to (item 2 of p) + ((item 2 of s) / 2)
            end if
          end repeat
        end if
      end try
    end repeat
    if bestx < 0 then
      return "none"
    end if
    -- NOTE: `integer & string` is a LIST in AppleScript ("1, a, 2")!
    -- Numbers must be text-converted before concatenation.
    return ((bestcx as integer) as text) & "," & ((bestcy as integer) as text)
  end tell
end tell
"""
    r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=10)
    out = (r.stdout or "").strip()
    if not out or out == "none":
        return False
    try:
        cx, cy = (int(v) for v in out.split(","))
    except Exception:
        return False
    subprocess.run(["python3", os.path.expanduser("~/church/zoom_click.py"), str(cx), str(cy)],
                   check=False, timeout=15)
    return True


def zoom_logout():
    """Sign out via the macOS menu bar (Electron in-window UI isn't in the AX tree).
    Current Zoom shows a confirmation dialog after the menu click (Cancel /
    Sign out) - accepted via a real mouse click on the right button."""
    # Current Zoom has NO confirmation dialog: the menu click goes straight to
    # the Login window. (Verified via AX on 2026-10-19.)
    script = '''
tell application "System Events"
  tell process "zoom.us"
    click menu item "Sign out of all accounts" of menu 1 of menu item "Sign out" of menu 1 of menu bar item "Zoom Workplace" of menu bar 1
    return "clicked"
  end tell
end tell
'''
    click_err = None
    for attempt in range(3):
        r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=20)
        if r.returncode == 0:
            break
        click_err = (r.stderr or r.stdout).strip()[:200]
        # stale open menu can block the next click - close it and retry
        try:
            subprocess.run(["osascript", "-e",
                            'tell application "System Events" to key code 53'],
                           check=False, timeout=10)
        except Exception:
            pass
        time.sleep(1)
    if click_err is not None:
        return {"ok": False, "detail": "sign-out menu click failed: %s" % click_err}
    # confirmation dialog handling: the dialog LAGS the menu click (it can
    # appear seconds later), so keep trying to accept it until we're on the
    # Login screen: click its right (Sign out) button with a real mouse event.
    for _ in range(20):
        if zoom_on_signin():
            return {"ok": True, "detail": "signed out; on Login screen"}
        try:
            if _zoom_accept_signout_dialog():
                log("zoom: sign-out confirmation dialog accepted (clicked right button)")
        except Exception as e:
            log("zoom: signout dialog accept error: %s" % e)
        time.sleep(1)
    return {"ok": True, "detail": "sign-out clicked (window state unclear)"}

def zoom_signout():
    """Full sign-out: 'Sign out of all accounts' (Zoom menu + confirm dialog),
    then quit the app so nothing lingers signed in."""
    with _ZOOM_OP_LOCK:
        return _zoom_signout_impl()

def _zoom_signout_impl():
    """Sign out of all accounts and leave the app on the Login screen.
    Deliberately does NOT quit the app: quitting lets Zoom auto-reauth the
    cached account on next launch, which is the 'sign out doesn't stick' bug."""
    global _LAST_ZOOM_ACCOUNT
    _ATT_CACHE.update(ts=0, count=None)
    _ATT_LAST = {"ok": True, "in_meeting": False, "count": None}
    op_begin("zoom sign-out")
    if not zoom_running():
        # nothing to sign out of (app closed); just forget the account
        _LAST_ZOOM_ACCOUNT = None
        op_finish(True, "zoom not running; nothing signed out")
        return {"ok": True, "detail": "zoom not running; nothing signed out"}
    op_step("Signing out of all accounts…")
    lo = zoom_logout()
    if lo.get("ok"):
        _LAST_ZOOM_ACCOUNT = None  # force a clean sign-out before next login
        op_finish(True, lo.get("detail") or "signed out")
    else:
        op_finish(False, lo.get("detail") or "sign-out failed")
    return lo

_ATT_CACHE = {"ts": 0, "count": None}   # status-menu count only (30s freshness)
_ATT_LAST = {"ok": True, "in_meeting": False, "count": None}  # last computed state

def zoom_attendees(live=False):
    """Current attendee count from Zoom's menu-bar status menu, which exposes
    a 'Participants (N)' item while in a meeting (Electron's in-window UI is
    AX-opaque, so the menu is the reliable source). Opens the menu briefly,
    reads it, closes it with Escape.

    IMPORTANT: this clicks menus, so it MUST NOT interleave with sign-in
    keystrokes (an Enter on an open menu activates the highlighted item -
    that has quit Zoom mid-login before). Takes the zoom op lock
    non-blocking; if a login/leave/sign-out is in flight, serves the last
    cached value instead.

    FRESHNESS: in_meeting is decided LIVE on every call (cheap window-name
    check, no clicking) so the buttons flip within one UI poll after
    join/leave. Only the count - which needs the menu click - is cached,
    30s, and only while in a meeting (that's what used to cause the
    'menu pops open/closed' spam when it ran on every poll)."""
    if not _ZOOM_OP_LOCK.acquire(timeout=0):
        return dict(_ATT_LAST, busy=True)
    try:
        return _zoom_attendees_impl()
    finally:
        _ZOOM_OP_LOCK.release()

# ------------------------------------------------- zoom api (participants) ---
_ZAPI_KEY = os.path.expanduser("~/church/zoom_api/api_key.pem")
_ZAPI_TOKEN = {"tok": None, "exp": 0}

def _zoom_api_cfg():
    z = CFG.get("zoom_api") or {}
    if not z.get("client_id") or not z.get("account_id"):
        return None
    return z

def _zoom_api_jwt(client_id):
    """ES256 JWT for Zoom S2S OAuth. Signing via openssl (stdlib-only host)."""
    def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=")

    def der_to_rs(der):
        i = 1
        ln = der[i]
        i += 1
        if ln & 0x80:
            i += (ln & 0x7f)
        parts = []
        for _ in range(2):
            assert der[i] == 0x02, "bad DER in signature"
            l2 = der[i + 1]
            i += 2
            parts.append(der[i:i + l2])
            i += l2
        r, sig_s = parts
        return r.rjust(32, b"\x00") + sig_s.rjust(32, b"\x00")

    h = b64u(json.dumps({"alg": "ES256", "typ": "JWT"}).encode())
    now = int(time.time())
    p = b64u(json.dumps({"iss": client_id, "exp": now + 300, "nbf": now,
                         "aud": "https://zoom.us/oauth"}).encode())
    si = h + b"." + p
    der = subprocess.run(["openssl", "dgst", "-sha256", "-sign", _ZAPI_KEY],
                         input=si, capture_output=True, timeout=15)
    if der.returncode != 0:
        raise RuntimeError("openssl sign failed: %s" % der.stderr.decode()[:150])
    return (si + b"." + b64u(der_to_rs(der.stdout))).decode()

def _zoom_api_token():
    z = _zoom_api_cfg()
    if not z:
        raise RuntimeError("Zoom API not configured (config.json: zoom_api.client_id + account_id)")
    now = time.time()
    if _ZAPI_TOKEN["tok"] and now < _ZAPI_TOKEN["exp"]:
        return _ZAPI_TOKEN["tok"]
    jwt = _zoom_api_jwt(z["client_id"])
    r = subprocess.run(["curl", "-s", "-X", "POST",
                        "https://zoom.us/oauth/token?grant_type=account_credentials"
                        "&account_id=" + str(z["account_id"]),
                        "-H", "Authorization: Bearer " + jwt,
                        "--max-time", "20"], capture_output=True, text=True, timeout=30)
    try:
        d = json.loads(r.stdout or "{}")
    except Exception:
        d = {}
    if "access_token" not in d:
        raise RuntimeError("Zoom token failed: %s" % (
            d.get("error_description") or d.get("error") or (r.stdout or r.stderr)[:150]))
    _ZAPI_TOKEN.update(tok=d["access_token"],
                       exp=now + max(60, int(d.get("expires_in", 3600)) - 120))
    return d["access_token"]

def _candidate_meeting_ids(tok_entry_key):
    ids = []
    def add(v):
        v = str(v or "").strip()
        if v and v not in ids:
            ids.append(v)
    if tok_entry_key:
        for m in _meetings():
            if m.get("zoom_account") == tok_entry_key:
                add(m.get("confno"))
    add((CFG.get("zoom") or {}).get("confno"))
    for m in _meetings():
        add(m.get("confno"))
    return ids

# ------------------------------------------------- zoom ocr (participants) ---
# Native Vision OCR helper (Swift, macOS 27). Prints per line:
#   text<TAB>x1<TAB>y1<TAB>w<TAB>h   (normalized 0..1, bottom-left origin)
_ZOCR_BIN = os.path.expanduser("~/church/zoom_api/zoom_ocr")

_ZOOM_PANEL_UI = ("Invite People", "Invite", "Participants", "Panelists",
                  "Attendees", "Chat", "Share", "More", "Hide", "Manage",
                  "Recording", "Stop", "Start", "Security", "Join with Audio",
                  "Mute", "Unmute", "Leave", "End", "Settings", "Help", "View")

def _ocr_lines(path):
    r = subprocess.run([_ZOCR_BIN, path], capture_output=True, text=True, timeout=90)
    if r.returncode != 0:
        raise RuntimeError("zoom_ocr failed: %s" % (r.stderr or r.stdout)[:200])
    out = []
    for ln in r.stdout.splitlines():
        parts = ln.split("\t")
        if len(parts) != 5:
            continue
        try:
            x1, y1, w, h = (float(v) for v in parts[1:5])
        except ValueError:
            continue
        out.append({"text": parts[0], "x": x1, "y": y1, "w": w, "h": h})
    return out

def _win_lines(lines, rect, screen):
    """Convert full-screen normalized OCR boxes (bottom-left origin) to
    window-relative coords (top-left origin, 0..1)."""
    px, py, w, h = rect
    sw, sh = screen
    res = []
    for L in lines:
        x_pt = L["x"] * sw
        y_top_pt = (1.0 - L["y"] - L["h"]) * sh
        xr = (x_pt - px) / w
        yr = (y_top_pt - py) / h
        if -0.02 <= xr <= 1.02 and -0.02 <= yr <= 1.02:
            res.append(dict(L, xr=xr, yr=yr, xc=xr + L["w"] * sw / w * 0.5))
    return res

def _parse_names(win):
    """Extract participant names from window-relative OCR lines.
    Anchor = the 'Participants (N)' header; names are the text lines in the
    panel column below it (above the bottom toolbar)."""
    header = None
    for L in win:
        if re.search(r"Participants\s*\(\d+\)", L["text"]):
            header = L
            break
    if header is None:
        return None
    hx, hy = header["xc"], header["yr"]
    names = []
    for L in win:
        t = L["text"].strip()
        if not t or L is header:
            continue
        # must be in the panel column and below the header, above the toolbar
        if L["xc"] < hx - 0.10 or L["xc"] > hx + 0.45:
            continue
        if L["yr"] < hy - 0.02 or L["yr"] > 0.88:
            continue
        low = t.lower()
        if any(u.lower() in low for u in _ZOOM_PANEL_UI):
            continue
        if re.fullmatch(r"[0-9,\.\s:apmPM\+\-]{1,12}", t):
            continue
        words = t.split()
        if len(words) > 9:
            continue
        if not re.search(r"[A-Za-z]", t):
            continue
        names.append({"name": t, "host": "host" in low or "Host" in t, "yr": L["yr"]})
    names.sort(key=lambda x: x["yr"])
    dedup = []
    for x in names:
        if not dedup or dedup[-1]["name"] != x["name"]:
            dedup.append(x)
    return [{"name": x["name"], "host": x["host"]} for x in dedup]

def zoom_ocr_participants():
    """Live participant names by opening the panel, screenshotting the
    window, and running native Vision OCR. Leaves the panel open."""
    if not zoom_running():
        raise RuntimeError("Zoom is not running")
    if "Zoom Webinar" not in _zoom_window_names():
        raise RuntimeError("no active Zoom meeting window found")
    rect = zoom_window_rect()
    if not rect:
        raise RuntimeError("cannot read the Zoom window position")
    screen = (1920, 1080)
    # main display size in points via Quartz (no osascript, no TCC prompt)
    try:
        out = subprocess.run([_ZOCR_BIN, "--screen"],
                             capture_output=True, text=True, timeout=10)
        v = out.stdout.strip().split("x")
        if len(v) == 2 and int(v[0]) > 100:
            screen = (int(v[0]), int(v[1]))
    except Exception:
        pass

    def capture_and_ocr():
        out = "/tmp/zoom_att_%d.png" % int(time.time())
        r = subprocess.run(["screencapture", "-x", out], capture_output=True, timeout=30)
        try:
            if r.returncode == 0 and os.path.exists(out):
                return _parse_names(_win_lines(_ocr_lines(out), rect, screen))
        finally:
            try:
                os.unlink(out)
            except OSError:
                pass
        return None

    # Participants button: 3rd toolbar control, ~0.36 of window width
    # (calibrated 2026-10-28 from a live screenshot; 0.42 would hit Chat)
    bx = rect[0] + int(rect[2] * 0.36)
    by = rect[1] + int(rect[3] * 0.94)
    names = capture_and_ocr()
    if names is None:
        zoom_mouse_click(bx, by)  # open (or re-open) the panel
        time.sleep(1.6)
        names = capture_and_ocr()
    if names is None:
        zoom_mouse_click(bx, by)
        time.sleep(1.6)
        names = capture_and_ocr()
    if names is None:
        raise RuntimeError("could not read the participant panel (OCR found no 'Participants (N)' header)")
    return {"ok": True, "source": "zoom-ocr", "count": len(names),
            "participants": names, "fetched_at": time.time()}

# ------------------------------------------------- zoom ax (participants) ---
# Reads Zoom's "Participants" window from its accessibility tree via
# System Events (AppleScript). Runs in-process under the dashboard's
# existing Automation grant - no child binary, no per-binary TCC dance.
# For webinars it switches to the Attendees tab (the congregation list).
# Exact text, host flags, per-tab counts.

_ZAX_READ_SCRIPT = r'''
on run
  tell application "System Events"
    tell process "zoom.us"
      -- 1) open the Participants window if it is closed
      set winNames to name of every window
      set hasP to false
      repeat with n in winNames
        if n starts with "Participants" then set hasP to true
      end repeat
      if not hasP then
        set targetW to missing value
        repeat with w in (every window)
          set wn to name of w as text
          if wn does not start with "Participants" and wn does not contain "Workplace" and wn does not contain "Login" then
            set targetW to w
            exit repeat
          end if
        end repeat
        if targetW is missing value then error "no meeting window found"
        set clicked to false
        repeat with b in (every button of targetW)
          set d to ""
          try
            set d to description of b
          end try
          if (d as text) contains "articipant" then
            click b
            delay 0.9
            set clicked to true
            exit repeat
          end if
        end repeat
        if not clicked then error "participants button not found"
      end if
      -- 2) read tab counts + switch to the Attendees tab (the congregation list)
      set pwin to first window whose name starts with "Participants"
      set wname to name of pwin as text
      set panC to -1
      set attC to -1
      set attTab to missing value
      repeat with b in (every button of pwin)
        set d to ""
        try
          set d to description of b
        end try
        set dl to d as text
        if dl starts with "Panelists" then set panC to my axdigits(dl)
        if dl starts with "Attendees" then
          set attC to my axdigits(dl)
          set attTab to b
        end if
      end repeat
      if attTab is not missing value then
        try
          click attTab
          delay 0.6
        end try
      end if
      -- 3) read the list rows (materialize "entire contents" before iterating -
      --    System Events quirk: it fails inside the repeat-in clause)
      set pwin to first window whose name starts with "Participants"
      set ol to outline 1 of scroll area 1 of pwin
      set rowCount to count of rows of ol
      set nameLines to {}
      repeat with i from 1 to rowCount
        set t to ""
        set ec to entire contents of row i of ol
        repeat with e in ec
          if (class of e) is static text then
            try
              set t to value of e as text
            end try
            exit repeat
          end if
        end repeat
        if t is not "" then set end of nameLines to t
      end repeat
      set out to wname & linefeed & (panC as text) & linefeed & (attC as text) & linefeed
      if (count of nameLines) > 0 then
        set AppleScript's text item delimiters to linefeed
        set out to out & (nameLines as text)
      end if
      return out
    end tell
  end tell
end run

on axdigits(s)
  set digits to ""
  repeat with ch in (characters of (s as text))
    set c to ch as text
    if c is greater than or equal to "0" and c is less than or equal to "9" then
      set digits to digits & c
    end if
  end repeat
  if digits is "" then return -1
  return digits as integer
end axdigits
'''

def zoom_ax_participants():
    """Live participant names (attendee list) read from Zoom's accessibility
    tree via System Events. Opens the Participants window if needed."""
    if not zoom_running():
        raise RuntimeError("Zoom is not running")
    last = "no attempt"
    for _attempt in range(3):
        r = subprocess.run(["osascript", "-e", _ZAX_READ_SCRIPT],
                           capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            lines = (r.stdout or "").strip().split("\n")
            if len(lines) >= 3:
                try:
                    pan_c, att_c = int(lines[1].strip()), int(lines[2].strip())
                except ValueError:
                    pan_c = att_c = -1
                raw = lines[3:] if len(lines) > 3 else []
                names = []
                for t in raw:
                    t = t.strip()
                    if not t:
                        continue
                    name = t.split("(", 1)[0].strip() if "(" in t and ")" in t else t
                    if name:
                        names.append({"name": name, "host": "host" in t.lower()})
                return {"ok": True, "source": "zoom-ax",
                        "count": len(names), "participants": names,
                        "panelists": pan_c, "attendees": att_c,
                        "fetched_at": time.time()}
        last = (r.stderr or r.stdout or "rc=%d" % r.returncode).strip()[:250]
        time.sleep(1.2)
    raise RuntimeError("could not read participants via Accessibility: %s" % last)
def zoom_participants():
    """Participant names for the UI. Accessibility tree first (exact text) -
    but Zoom renders the participant list AX-opaque, so when AX yields no
    names we fall back to Vision OCR of the panel. Tab counts are kept from
    whichever source reports them."""
    ax = None
    ax_err = None
    try:
        ax = zoom_ax_participants()
    except Exception as e:
        ax_err = str(e)[:150]
    if ax and ax.get("participants"):
        ax["source"] = "zoom-ax"
        return ax
    warnings = []
    if ax_err:
        warnings.append("ax: %s" % ax_err)
    elif ax is not None:
        warnings.append("ax: read ok but list is AX-opaque (no names); using Vision OCR")
    r = zoom_ocr_participants()
    if r.get("participants") is None:
        r["participants"] = []
    if ax and r.get("panelists") in (None, -1):
        r["panelists"] = ax.get("panelists", -1)
        r["attendees"] = ax.get("attendees", -1)
    r["warnings"] = warnings
    r["source"] = "zoom-ocr"
    return r

def zoom_api_participants(meeting_id=None, tok_entry_key=None):
    """Live participant names via the Zoom Meetings API (S2S OAuth, meeting:read)."""
    tok = _zoom_api_token()
    ids = ([str(meeting_id).strip()] if meeting_id and str(meeting_id).strip()
           else []) + _candidate_meeting_ids(tok_entry_key)
    last_err = None
    for mid in ids:
        r = subprocess.run(["curl", "-s", "--max-time", "15",
                            "https://api.zoom.us/v2/meetings/%s/participants" % mid,
                            "-H", "Authorization: Bearer " + tok],
                           capture_output=True, text=True, timeout=25)
        try:
            d = json.loads(r.stdout or "{}")
        except Exception:
            last_err = "meeting %s: unparseable (%s)" % (mid, r.stdout[:80])
            continue
        if r.returncode == 0 and "participants" in d:
            names = []
            for p in d.get("participants", []):
                nm = ((p.get("user") or {}).get("name")) or p.get("user_id") or "?"
                names.append({"name": nm, "host": bool(p.get("host"))})
            return {"ok": True, "source": "zoom-api", "meeting_id": mid,
                    "count": len(names), "participants": names,
                    "fetched_at": time.time()}
        last_err = "meeting %s: %s" % (mid, d.get("message") or d.get("error") or r.stdout[:80])
    raise RuntimeError(last_err or "no meeting id candidates")

def _zoom_window_names():
    script = r'''
tell application "System Events"
  if (exists (first process whose name is "zoom.us")) then
    tell process "zoom.us"
      try
        return ((name of windows) as text)
      on error
        return ""
      end try
    end tell
  end if
  return ""
end tell
'''
    try:
        r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except Exception:
        return ""

def _zoom_attendees_impl():
    global _ATT_LAST
    if not zoom_running():
        _ATT_LAST = {"ok": True, "in_meeting": False, "count": None}
        _ATT_CACHE["count"] = None  # count is stale after any leave
        return dict(_ATT_LAST)
    # in_meeting is ALWAYS live: cheap window-name check, no UI clicking.
    # (The old 45s result cache served the pre-join state for up to 45s,
    # which is what delayed the button flip after joining.)
    if "Zoom Webinar" not in _zoom_window_names():
        _ATT_LAST = {"ok": True, "in_meeting": False, "count": None}
        _ATT_CACHE["count"] = None  # count is stale after any leave
        return dict(_ATT_LAST)
    script = r'''
tell application "System Events"
  tell process "zoom.us"
    if (count of menu bars) < 2 then
      return "no-status-menu"
    end if
    click menu bar item 1 of menu bar 2
    delay 0.8
    set out to "none"
    try
      repeat with mi in (menu items of menu 1 of menu bar item 1 of menu bar 2)
        try
          set n to (name of mi)
          if n starts with "Participants" then
            set out to n
          end if
        end try
      end repeat
    end try
    try
      key code 53
    end try
    return out
  end tell
end tell
'''
    # count: best-effort via the status menu, cached 30s while in the
    # meeting (the click must stay rare - that's what caused the
    # menu-pop spam). Zoom may cancel the click (modal dialog, System
    # Events busy) - fine: in_meeting truth is the window check above;
    # count just stays None. Never error out here.
    count = _ATT_CACHE.get("count")
    if count is not None and (time.time() - _ATT_CACHE["ts"]) >= 30:
        count = None
    if count is None:
        try:
            r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=20)
            m = re.search(r"Participants \((\d+)\)", r.stdout or "")
            if m:
                count = int(m.group(1))
        except Exception:
            pass
        _ATT_CACHE.update(ts=time.time(), count=count)
    _ATT_LAST = {"ok": True, "in_meeting": True, "count": count}
    return dict(_ATT_LAST)

# -------------------------------------------------------------- sequences ---
def svc_start(profile_id=None):
    steps = []

    def add(name, ok, detail=""):
        steps.append({"step": name, "ok": bool(ok), "detail": detail})
        op_step("%s \u2014 %s" % (name, detail or ("ok" if ok else "failed")))

    mid = profile_id or _default_profile_id()
    m = _meeting(mid)
    if m is None:
        return {"ok": False, "steps": [
            {"step": "profile", "ok": False,
             "detail": "no meeting profile '%s' (check config meetings[])" % mid}]}
    op_begin("service start (%s)" % m["name"])

    if obs_running():
        add("obs running", True, "already running")
    else:
        subprocess.run(["open", "-a", "OBS", "--args", "--startvirtualcam"], check=False)
        add("obs running", True, "launched OBS with virtual camera")
    op_step("Waiting for OBS websocket…")
    t0 = time.time()
    while OBS and not OBS.connected and time.time() - t0 < 20:
        time.sleep(1)
    add("obs websocket", bool(OBS and OBS.connected),
        "connected" if (OBS and OBS.connected) else "not connected (check OBS: Tools > OBS WebSocket)")
    if OBS and OBS.connected:
        def _vcam_active():
            vs = OBS.rpc("GetVirtualCamStatus", timeout=6)
            return bool(vs.get("outputActive", vs.get("enabled")))
        try:
            if _vcam_active():
                add("virtual camera", True, "already active")
            else:
                try:
                    OBS.rpc("StartVirtualCam", timeout=5)
                except Exception:
                    OBS.rpc("SetVirtualCamEnabled", {"enabled": True}, timeout=5)
                time.sleep(1)
                try:
                    active = _vcam_active()
                except Exception:
                    active = True
                add("virtual camera", active, "enabled" if active else "could not enable")
        except Exception as e:
            add("virtual camera", False, str(e)[:120])
    op_step("Joining Zoom as %s…" % m["name"])
    try:
        r = zoom_join(m["confno"], m["zoom_account"])
        add("zoom join (%s)" % m["name"], r["ok"], r["detail"])
    except Exception as e:
        add("zoom join (%s)" % m["name"], False, str(e)[:150])
    sp = m.get("start_preset")
    if sp is None:
        sp = CFG.get("service", {}).get("start_preset")
    if CAM is not None and sp is not None:
        r = CAM.cmd("ptzcmd", "poscall", sp)
        add("camera preset %s" % sp, r.get("ok"), json.dumps(r.get("result", r.get("error", "")))[:120])
    sc = m.get("scene") or CFG.get("service", {}).get("start_scene")
    if OBS and OBS.connected and sc:
        try:
            OBS.rpc("SetCurrentProgramScene", {"sceneName": sc}, timeout=5)
            add("obs scene", True, sc)
        except Exception as e:
            add("obs scene", False, str(e)[:120])
    ok_all = all(s["ok"] for s in steps)
    op_finish(ok_all, "all steps completed" if ok_all else "completed with failures")
    global _SVC_ACTIVE
    _SVC_ACTIVE = True  # a start sequence ran - Stop must be offered
    return {"ok": ok_all, "steps": steps}

def svc_stop():
    steps = []

    def add(name, ok, detail=""):
        steps.append({"step": name, "ok": bool(ok), "detail": detail})
        op_step("%s \u2014 %s" % (name, detail or ("ok" if ok else "failed")))

    op_begin("service stop")
    try:
        r = zoom_full_close()
        add("zoom close", r["ok"], r["detail"])
    except Exception as e:
        add("zoom leave", False, str(e)[:150])
    park = CFG.get("service", {}).get("park_preset")
    if CAM is not None:
        if park is not None:
            r = CAM.cmd("ptzcmd", "poscall", park)
            add("camera park", r.get("ok"), "preset %s" % park)
        else:
            r = CAM.cmd("ptzcmd", "home")
            add("camera park", r.get("ok"), "home position")
    if CFG.get("service", {}).get("stop_obs", False):
        subprocess.run(["osascript", "-e", 'tell application "OBS" to quit'], check=False)
        add("obs quit", True, "told OBS to quit")
    else:
        add("obs", True, "left running (virtual camera stays up)")
    ok_all = all(s["ok"] for s in steps)
    op_finish(ok_all, "all steps completed" if ok_all else "completed with failures")
    global _SVC_ACTIVE
    _SVC_ACTIVE = not ok_all  # keep "active" if the stop itself failed
    return {"ok": ok_all, "steps": steps}

# ------------------------------------------------------------------- state -
_OBS_CACHE = {}  # last-known-good values so a transient RPC failure can't wipe the UI

def build_state():
    st = {"obs": {"connected": False}, "camera": {"reachable": False, "stream": None},
          "zoom": {"running": False, "account": _LAST_ZOOM_ACCOUNT},
          "obs_running": obs_running(), "svc": {"active": _SVC_ACTIVE}}
    if OBS:
        if OBS.connected:
            st["obs"]["connected"] = True
            try:
                sl = OBS.rpc("GetSceneList", timeout=6)
                raw = list(sl.get("scenes", []))
                # Order like OBS/Blade: sceneIndex DESCENDING (newest first).
                # Raw GetSceneList is ascending creation order = the REVERSE
                # of OBS's displayed order (user confirmed 2026-10-21).
                if all(isinstance(sc.get("sceneIndex"), int) for sc in raw):
                    raw.sort(key=lambda sc: sc["sceneIndex"], reverse=True)
                else:
                    raw.reverse()
                scenes = [x for x in (sc.get("name") or sc.get("sceneName")
                                     for sc in raw) if x]
                if scenes:
                    _OBS_CACHE["scenes"] = scenes
            except Exception:
                pass
            try:
                cur = OBS.rpc("GetCurrentProgramScene", timeout=6).get("sceneName")
                if cur:
                    _OBS_CACHE["current"] = cur
            except Exception:
                pass
            try:
                rs = OBS.rpc("GetRecordStatus", timeout=6)
                _OBS_CACHE["recording"] = bool(rs.get("outputActive", rs.get("outputState") == "recording"))
            except Exception:
                pass
            try:
                vs = OBS.rpc("GetVirtualCamStatus", timeout=6)
                _OBS_CACHE["vcam"] = bool(vs.get("outputActive", vs.get("enabled")))
            except Exception:
                pass
            st["obs"]["scenes"] = _OBS_CACHE.get("scenes", [])
            st["obs"]["current"] = _OBS_CACHE.get("current")
            st["obs"]["recording"] = _OBS_CACHE.get("recording", False)
            st["obs"]["vcam"] = _OBS_CACHE.get("vcam")
        else:
            st["obs"]["error"] = "not connected"
            st["obs"]["scenes"] = _OBS_CACHE.get("scenes", [])
            st["obs"]["current"] = _OBS_CACHE.get("current")
    if CAM:
        ok, err = CAM.reachable()
        st["camera"]["reachable"] = ok
        if err:
            st["camera"]["error"] = err
    st["camera"]["stream"] = ("stream" if STREAM_TARGET else None)
    st["zoom"]["running"] = zoom_running()
    return st

# --------------------------------------------------------------------- http -
UI_HTML = """<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Church OBS Remote</title>
<style>
:root{--bg:#0e1116;--card:#161b23;--line:#232b37;--fg:#e8edf4;--mut:#8b98ab;--acc:#4f8cff;--ok:#31c48d;--bad:#f0564f;--warn:#f2b544}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
button,.chip{user-select:none;-webkit-user-select:none;-webkit-touch-callout:none;touch-action:manipulation}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:14px 14px 40px}
.wrap{max-width:560px;margin:0 auto}
h1{font-size:19px;margin:6px 2px 12px;display:flex;align-items:center;gap:10px}
h1 .dots{margin-left:auto;display:flex;gap:6px;font-size:12px;color:var(--mut);align-items:center}
.dot{width:9px;height:9px;border-radius:50%;background:#3a4656;display:inline-block}
.dot.on{background:var(--ok)}.dot.off{background:var(--bad)}
label.lbl{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut);margin:18px 2px 7px;display:block}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px;margin-bottom:12px}
.btn{display:block;width:100%;border:1px solid var(--line);background:#1d2430;color:var(--fg);border-radius:11px;padding:13px 14px;font-size:16px;font-weight:600;margin-top:8px;cursor:pointer;text-align:center}
.btn:active{transform:scale(.985)}
.pad .btn,.zoomcol .btn{transition:background .12s,border-color .12s,transform .06s,box-shadow .12s}
.pad .btn:hover,.zoomcol .btn:hover{background:#232c3b}
.pad .btn:active,.zoomcol .btn:active{background:#2f3b50;border-color:#5a7196;color:#fff;transform:scale(1.05);box-shadow:0 0 14px rgba(125,165,255,.45),inset 0 0 8px rgba(125,165,255,.25)}
.btn.big{font-size:19px;padding:17px}
.btn.green{background:#12351f;border-color:#1e5c38;color:#7ce3a8}
.btn.red{background:#3a1715;border-color:#6e2a26;color:#ff9d94}
.btn.blue{background:#15263f;border-color:#274a7a;color:#9cc3ff}
.btn:disabled{opacity:.55;cursor:wait}
.btn .spin{display:inline-block;width:1em;height:1em;border:2px solid rgba(255,255,255,.3);border-top-color:currentColor;border-radius:50%;animation:ctspin .8s linear infinite;vertical-align:-.15em;margin-right:.4em}
@keyframes ctspin{to{transform:rotate(360deg)}}
.row{display:flex;gap:8px}.row .btn{flex:1;margin-top:8px}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}
.chip{border:1px solid var(--line);background:#1d2430;border-radius:999px;padding:9px 15px;font-size:15px;font-weight:600;cursor:pointer;font-family:inherit;color:var(--fg)}
.chip.cur{background:#1c3a66;border-color:#2f5da8;color:#cfe1ff}
.chip:active{transform:scale(.96)}
.padrow{display:flex;gap:12px;align-items:center;justify-content:center;margin-top:10px}
.pad{display:grid;grid-template-columns:repeat(3,64px);grid-auto-rows:52px;gap:8px}
.pad .btn{width:64px;height:52px;margin:0;font-size:20px;padding:0}
.zoomcol{display:flex;flex-direction:column;gap:8px}
.zoomcol .btn{width:52px;height:52px;margin:0;font-size:18px;padding:0}
.presetbox{margin-top:12px;border-top:1px solid var(--line);padding-top:8px}
.presetbox summary{cursor:pointer;font-size:14px;font-weight:600;color:var(--mut);padding:4px 2px}
.stream{width:100%;border-radius:10px;border:1px solid var(--line);background:#000;margin-top:4px;min-height:90px}
.mut{color:var(--mut);font-size:13px}
.result{font-size:14px;margin-top:10px;white-space:pre-wrap;color:var(--mut)}
.result b{color:var(--fg)}
.err{color:var(--bad)}
#gate{position:fixed;inset:0;background:var(--bg);display:flex;align-items:center;justify-content:center;z-index:9}
#gate .card{width:min(400px,92vw)}
.hidden{display:none!important}
.attmodal{position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:50;display:flex;align-items:center;justify-content:center;padding:18px}
.attbox{background:#12161d;border:1px solid var(--line);border-radius:14px;min-width:280px;max-width:420px;width:100%;max-height:75vh;display:flex;flex-direction:column;box-shadow:0 12px 40px rgba(0,0,0,.5)}
.attbox .hd{display:flex;align-items:center;justify-content:space-between;padding:13px 16px;border-bottom:1px solid var(--line)}
.attbox .bd{padding:10px 16px 14px;overflow-y:auto}
.attlist{list-style:none;margin:8px 0 0;padding:0}
.attlist li{padding:7px 2px;border-bottom:1px solid rgba(255,255,255,.06);font-size:15px}
.attlist li:last-child{border-bottom:none}
.attlist li .h{opacity:.6;font-size:12px;margin-left:6px}
</style></head>
<body><div class="wrap">
<div id="gate"><div class="card">
  <h1 style="margin-top:0">Church OBS Remote</h1>
  <div class="mut" id="gateMsg">Enter your access token.</div>
  <input id="tok" type="password" placeholder="token" style="width:100%;margin-top:12px;background:#0b0e13;border:1px solid var(--line);color:var(--fg);border-radius:10px;padding:12px;font-size:16px">
  <button class="btn blue" id="gateGo">Unlock</button>
</div></div>

<h1>Church OBS Remote <span id="scopeName" class="mut" style="font-size:13px;font-weight:400"></span>
  <span class="dots">
    <span class="dot" id="dObs"></span><span>OBS</span>
    <span class="dot" id="dCam"></span><span>Cam</span>
    <span class="dot" id="dZoom"></span><span>Zoom</span>
    <span id="updAge" class="mut" style="font-size:11px"></span>
  </span></h1>
<div id="netBanner" class="hidden" style="background:#3a1715;border:1px solid #6e2a26;color:#ff9d94;border-radius:11px;padding:10px 14px;font-size:14px;font-weight:600;margin-bottom:12px" role="alert">⚠ Connection lost — retrying…</div>

<div class="card">
  <label class="lbl" style="margin-top:0">OBS — scenes</label>
  <div class="chips" id="scenes"><span class="mut">waiting for OBS…</span></div>
  <div class="result" id="obsResult" aria-live="polite"></div>
</div>

<div class="card">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:7px">
    <label class="lbl" style="margin-top:0">Preview</label>
    <span style="display:flex;align-items:center;gap:8px">
      <button class="btn" id="vcamBtn" style="display:inline-block;width:auto;margin-top:0;padding:5px 10px;font-size:12.5px;border-radius:9px">📷 Virtual cam</button>
      <span class="mut" id="fpsBadge" style="font-size:11px"></span>
    </span>
  </div>
  <img class="stream hidden" id="stream" alt="live view">
  <div class="mut hidden" id="noStream" style="margin-top:4px">Waiting for preview… (OBS must be running)</div>
</div>


<div class="card">
  <label class="lbl" style="margin-top:0">Camera — pan / tilt</label>
  <div class="padrow">
    <div class="pad">
      <span></span><button class="btn" data-mv="up" aria-label="pan up">▲</button><span></span>
      <button class="btn" data-mv="left" aria-label="pan left">◀</button><span></span><button class="btn" data-mv="right" aria-label="pan right">▶</button>
      <span></span><button class="btn" data-mv="down" aria-label="pan down">▼</button><span></span>
    </div>
    <div class="zoomcol">
      <button class="btn" data-mv="zoomin" aria-label="zoom in">＋</button>
      <button class="btn" data-mv="zoomout" aria-label="zoom out">－</button>
    </div>
  </div>
  <div class="mut" style="font-size:11.5px;margin-top:4px">Tap = fine \u00b7 hold ramps up \u00b7 release = stop</div>
  <div class="row" style="align-items:center;gap:10px;margin-top:8px">
    <label class="lbl" style="margin:0;white-space:nowrap">Max speed</label>
    <input id="ptzMax" type="range" min="10" max="100" step="5" value="50" style="flex:1;accent-color:var(--acc)">
    <span id="ptzMaxV" class="mut" style="font-size:12px;min-width:34px;text-align:right">50%</span>
  </div>
  <details class="presetbox" id="presetBox" style="display:none">
    <summary>Presets &amp; save</summary>
    <label class="lbl">Presets (recall)</label>
    <div class="chips" id="presets"></div>
    <div class="row">
      <input id="presetN" type="number" min="0" max="9" placeholder="0–9" style="flex:1;background:#0b0e13;border:1px solid var(--line);color:var(--fg);border-radius:10px;padding:11px;font-size:16px">
      <button class="btn" id="presetSave" style="flex:0 0 auto;width:auto;padding:11px 16px">Save here</button>
    </div>
  </details>
  <div class="result" id="camResult" aria-live="polite"></div>
</div>

<div class="card">
  <div class="mut" id="svcMsg">One-tap sequence: OBS up → Zoom joined (auto sign-in) → camera to start position.</div>
  <div id="profPick" style="display:none;margin-bottom:6px"><label class="lbl">Active congregation (admin)</label><div class="chips" id="profChips" style="margin-top:6px"></div></div>
  <div class="mut" id="schedLine" style="margin-bottom:8px;font-size:12px"></div>
  <div class="row">
    <button class="btn big green" id="svcStart">▶ Start Service</button>
    <button class="btn big red" id="svcStop">■ Stop Service</button>
  </div>
  <div class="result" id="svcResult" aria-live="polite"></div>
</div>

<div class="card">
  <div style="display:flex;align-items:baseline;justify-content:space-between;margin-bottom:7px">
    <label class="lbl" style="margin-top:0">Zoom</label>
    <span class="mut" id="attBadge" style="font-size:11px"></span>
    <span class="mut" id="zoomAcct" style="font-size:11px;margin-left:8px"></span>
  </div>
  <div class="row">
    <button class="btn blue" id="zLogin">🔑 Sign in</button>
    <button class="btn green" id="zJoin" style="display:none">▶ Join</button>
    <button class="btn red" id="zClose" style="display:none">⏻ Close</button>
    <button class="btn" id="attBtn" style="display:none" onclick="showAttendees()" title="Open the participant name list">📋 Names</button>
  </div>
  <div class="row" id="wbRow" style="display:none;gap:8px">
    <input id="wbId" type="text" inputmode="numeric" placeholder="webinar ID to join on demand" style="flex:1;min-width:0;background:#0b0e13;border:1px solid var(--line);color:var(--fg);border-radius:10px;padding:11px;font-size:15px">
    <button class="btn" id="zJoinId" style="flex:0 0 auto;width:auto;padding:11px 14px">🎯 Join ID</button>
  </div>
  <div class="mut" id="zoomHelp" style="margin-top:8px">Sign-in runs automatically when Join lands on the sign-in screen. Credentials live in the Mac Keychain.</div>
  <div class="result" id="zoomResult" aria-live="polite"></div>
</div>

<div style="margin-top:16px;padding-top:14px;border-top:1px solid var(--line)">
  <div id="activeRow" style="display:none;font-size:13.5px;line-height:1.7"></div>
  <div style="display:flex;gap:10px;margin-top:12px">
    <button class="btn" id="setup" style="display:none;width:auto;margin-top:0;flex:1">🔑 Set Zoom credentials</button>
    <button class="btn" id="signout" style="width:auto;margin-top:0;flex:1">🔒 Lock console</button>
  </div>
</div>
</div>

<div id="credModal" class="attmodal hidden" role="dialog" aria-modal="true" aria-label="Set Zoom credentials" onclick="if(event.target===this)this.classList.add('hidden')">
  <div class="attbox">
    <div class="hd"><b>🔑 Set Zoom credentials</b>
      <button class="btn" id="credClose" style="padding:6px 12px" onclick="document.getElementById('credModal').classList.add('hidden')" aria-label="close">✕</button>
    </div>
    <div class="bd">
      <label class="lbl" style="margin-top:0">Congregation</label>
      <select id="credAcc" style="width:100%;background:#0b0e13;border:1px solid var(--line);color:var(--fg);border-radius:10px;padding:11px;font-size:16px;margin-bottom:12px"></select>
      <label class="lbl">Zoom password</label>
      <input id="credPass" type="password" placeholder="password" style="width:100%;background:#0b0e13;border:1px solid var(--line);color:var(--fg);border-radius:10px;padding:12px;font-size:16px">
      <div class="mut" style="margin-top:8px">Saved to the Mac Keychain for this account.</div>
      <div class="result" id="credResult" aria-live="polite"></div>
    </div>
    <div style="padding:0 16px 14px"><button class="btn green" id="credSave" style="margin-top:4px">Save</button></div>
  </div>
</div>
<script>
window.__errlog=[];
function __errpush(t){window.__errlog.push(t);try{document.body.setAttribute("data-pageerr",JSON.stringify(window.__errlog.slice(-6)));}catch(x){}}
window.addEventListener("error",e=>__errpush("ERR@"+(e.lineno||"?")+" MSG="+(e.message||"")+(e.error&&e.error.stack?" STK="+e.error.stack.split("\\n").slice(0,5).join(" | "):"")));
window.addEventListener("unhandledrejection",e=>{const r=e.reason;__errpush("REJ "+String(r&&r.message||r))});
const T=()=>localStorage.getItem("ct")||"";
function gate(show){document.getElementById("gate").style.display=show?"flex":"none";document.getElementById("gate").classList.toggle("hidden",!show);}
async function api(path,body,method){
  const opts={method:method||(body!==undefined?"POST":"GET"),headers:{Authorization:"Bearer "+T()}};
  if(body!==undefined){opts.headers["Content-Type"]="application/json";opts.body=JSON.stringify(body);}
  const r=await fetch(path,opts);
  if(r.status===401){gate(true);throw new Error("token rejected");}
  // Read the body EXACTLY ONCE - calling r.json() and then r.text() in the
  // fallback throws "TypeError: Body is disturbed or locked" (the body is
  // consumed after the first read attempt).
  let d;
  const txt=await r.text();
  try{d=JSON.parse(txt);}catch(e){d={raw:txt.slice(0,200)};}
  if(!r.ok){throw new Error(d.error||d.detail||(d.raw?("HTTP "+r.status+": "+d.raw):("HTTP "+r.status)));}
  return d;
}
function esc(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
async function showAttendees(){
  const m=document.getElementById("attModal"), b=document.getElementById("attBody");
  m.classList.remove("hidden"); b.innerHTML="Loading…";
  try{
    const d=await api("/api/zoom/participants");
    if(d.participants && d.participants.length){
      // names are escaped via esc() before insertion — safe against HTML injection
      var hdr=d.count+" in meeting";
      if(typeof d.panelists!=="undefined"&&d.panelists>=0){hdr=d.count+" attendee"+(d.count===1?"":"s")+" · "+d.panelists+" panelist"+(d.panelists===1?"":"s");}
      b.innerHTML="<div class='mut'>"+hdr+" · "+new Date(d.fetched_at*1000).toLocaleTimeString()+"</div>"+
        "<ul class='attlist'>"+d.participants.map(p=>"<li>"+esc(p.name)+(p.host?"<span class='h'>host</span>":"")+"</li>").join("")+"</ul>";
    } else {
      var hdr2="";
      if(typeof d.panelists!=="undefined"&&d.panelists>=0){hdr2=" (panelists: "+d.panelists+", attendees: "+d.attendees+")";}
      b.innerHTML="<div class='mut'>No attendees in the list"+hdr2+" (meeting may not be in progress for this account).</div>";
    }
  }catch(e){
    b.innerHTML="<div class='err'>"+esc(e.message||String(e))+"</div><div class='mut' style='margin-top:8px'>Make sure the meeting is active in this account's Zoom client, then try again.</div>";
  }
}
function res(id,ok,txt){const e=document.getElementById(id);if(!e)return;e.innerHTML=(ok?"✔ ":"✘ ")+(txt||"").replace(/</g,"&lt;");e.classList.toggle("err",!ok);}
async function act(id,fn,rid,busy){
  const b=document.getElementById(id);b.disabled=true;
  const orig=b.innerHTML;
  b.innerHTML='<span class="spin"></span>'+(busy||"Working…");
  let poll=null;
  const tick=async()=>{try{
    const o=await api("/api/operation");
    if(rid&&o&&o.op&&!o.done&&o.step){const e=document.getElementById(rid);
      if(e){e.innerHTML='<span class="mut">⏳ '+String(o.step).replace(/</g,"&lt;")+'</span>';e.classList.remove("err");}}
  }catch(x){}};
  if(rid){tick();poll=setInterval(tick,900);}
  try{const d=await fn();return d;}catch(e){if(rid)res(rid,false,String(e.message||e));throw e;}
  finally{if(poll)clearInterval(poll);b.disabled=false;b.innerHTML=orig;}
}
document.getElementById("gateGo").onclick=async()=>{
  const t=document.getElementById("tok").value.trim();
  if(!t)return;
  localStorage.setItem("ct",t);
  try{await api("/api/state");gate(false);refresh();}
  catch(e){document.getElementById("gateMsg").textContent="Token rejected. "+(e.message||"");}
};
document.getElementById("signout").onclick=()=>{localStorage.removeItem("ct");gate(true);};
async function openCredModal(){
  const m=document.getElementById("credModal");
  const sel=document.getElementById("credAcc");
  sel.innerHTML="<option>loading…</option>";
  document.getElementById("credResult").textContent="";
  m.classList.remove("hidden");
  try{
    const p=await api("/api/profiles");
    const names=(p.meetings||[]).map(x=>x.name);
    if(!names.length)throw new Error("no congregations in the meeting table");
    sel.innerHTML=names.map(x=>"<option>"+esc(x)+"</option>").join("");
  }catch(e){
    sel.innerHTML="";
    document.getElementById("credResult").textContent=String(e.message||e);
  }
  document.getElementById("credPass").focus();
}
document.getElementById("setup").onclick=openCredModal;
document.getElementById("credSave").onclick=async()=>{
  const acc=document.getElementById("credAcc").value, pw=document.getElementById("credPass").value;
  if(!acc||!pw){document.getElementById("credResult").textContent="pick a congregation and enter a password";return;}
  const b=document.getElementById("credSave");b.disabled=true;
  try{
    await api("/setup",{account:acc,zoom_pass:pw});
    document.getElementById("credPass").value="";
    document.getElementById("credModal").classList.add("hidden");
    res("zoomResult",true,"Zoom password saved to Keychain for "+acc);
  }catch(e){
    document.getElementById("credResult").textContent=String(e.message||e);
  }finally{b.disabled=false;}
};
document.getElementById("svcStart").onclick=async()=>{try{const d=await act("svcStart",()=>api("/api/service/start",undefined,"POST"),"svcResult");
  document.getElementById("svcResult").innerHTML=d.steps.map(s=>`<b>${s.ok?"✔":"✘"} ${s.step}</b> — ${String(s.detail).replace(/</g,"&lt;")}`).join("\\n");refresh();}catch(e){res("svcResult",false,String(e.message||e));}};
document.getElementById("svcStop").onclick=async()=>{try{const d=await act("svcStop",()=>api("/api/service/stop",undefined,"POST"),"svcResult");
  document.getElementById("svcResult").innerHTML=d.steps.map(s=>`<b>${s.ok?"✔":"✘"} ${s.step}</b> — ${String(s.detail).replace(/</g,"&lt;")}`).join("\\n");refresh();}catch(e){res("svcResult",false,String(e.message||e));}};
document.querySelectorAll("[data-mv]").forEach(b=>{
  const mv=b.dataset.mv;
  const stopFor=(mv==="zoomin"||mv==="zoomout")?"zoomstop":"ptzstop";
  if(mv==="ptzstop"||mv==="zoomstop"){
    b.onclick=()=>api("/api/camera/move",{action:mv}).catch(e=>res("camResult",false,String(e.message||e)));
    return;
  }
  let ramp1=null, ramp2=null, hardT=null, moving=false;
  const stop=()=>{
    if(ramp1){clearTimeout(ramp1);ramp1=null;}
    if(ramp2){clearTimeout(ramp2);ramp2=null;}
    if(hardT){clearTimeout(hardT);hardT=null;}
    moving=false;
    api("/api/camera/move",{action:stopFor}).catch(()=>{});
  };
  const pmax=()=>Math.max(10,Math.min(100,parseInt(localStorage.getItem("ptzmax")||"50",10)||50));
  b.addEventListener("pointerdown",e=>{e.preventDefault();
    moving=true;
    res("camResult",true,"moving "+mv+" (fine)");
    api("/api/camera/move",{action:mv}).catch(e2=>res("camResult",false,String(e2.message||e2)));
    const mx=pmax();
    ramp1=setTimeout(()=>{
      if(!moving)return;
      res("camResult",true,"moving "+mv+" (medium \u00b7 "+Math.max(5,Math.round(mx/2))+"%)");
      api("/api/camera/move",{action:mv,speed:Math.max(5,Math.round(mx/2))}).catch(()=>{});
    },400);
    ramp2=setTimeout(()=>{
      if(!moving)return;
      res("camResult",true,"moving "+mv+" (fast \u00b7 "+mx+"%)");
      api("/api/camera/move",{action:mv,speed:mx}).catch(()=>{});
    },1000);
    hardT=setTimeout(()=>{
      if(!moving)return;
      stop();
      res("camResult",true,mv+" \u00b7 30s safety stop \u2014 tap again to continue");
    },30000);});
  b.addEventListener("pointerup",e=>{e.preventDefault();if(moving)stop();});
  b.addEventListener("pointercancel",()=>{if(moving)stop();});
  b.addEventListener("pointerleave",()=>{if(moving)stop();});
  b.addEventListener("contextmenu",e=>e.preventDefault());
  b.style.touchAction="manipulation";
});
(function(){
  const sl=document.getElementById("ptzMax"),v=document.getElementById("ptzMaxV");
  if(!sl)return;
  const cur=Math.max(10,Math.min(100,parseInt(localStorage.getItem("ptzmax")||"50",10)||50));
  sl.value=cur;v.textContent=cur+"%";
  sl.addEventListener("input",()=>{v.textContent=sl.value+"%";localStorage.setItem("ptzmax",sl.value);});
})();
document.getElementById("presetSave").onclick=async()=>{const n=document.getElementById("presetN").value;
  if(n==="")return;try{await act("presetSave",()=>api("/api/camera/preset",{n:+n,save:true}),"camResult");res("camResult",true,"saved position to preset "+n);}catch(e){res("camResult",false,String(e.message||e));}};
document.getElementById("vcamBtn").onclick=async()=>{try{const d=await api("/api/state");
  await act("vcamBtn",()=>api("/api/obs/vcam",{on:!d.obs.vcam}),"obsResult");
  res("obsResult",true,(d.obs.vcam?"virtual camera off":"virtual camera on"));refresh();}catch(e){res("obsResult",false,String(e.message||e));}};
document.getElementById("zLogin").onclick=async()=>{try{const d=await act("zLogin",()=>api("/api/zoom/login",undefined,"POST"),"zoomResult","Signing in\u2026");res("zoomResult",d.ok,d.detail);if(d.ok)refresh();}catch(e){res("zoomResult",false,String(e.message||e));}};
document.getElementById("zJoin").onclick=async()=>{try{const d=await act("zJoin",()=>api("/api/zoom/join",undefined,"POST"),"zoomResult","Joining\u2026");res("zoomResult",d.ok,d.detail);refresh();}catch(e){res("zoomResult",false,String(e.message||e));}};
document.getElementById("zClose").onclick=async()=>{if(!confirm("End any meeting, sign out of Zoom, and close the app?"))return;
  try{const d=await act("zClose",()=>api("/api/zoom/close",undefined,"POST"),"zoomResult","Closing\u2026");res("zoomResult",d.ok,d.detail);refresh();}catch(e){res("zoomResult",false,String(e.message||e));}};
document.getElementById("zJoinId").onclick=async()=>{
  const idv=(document.getElementById("wbId").value||"").replace(/\\D/g,"");
  if(!idv){res("zoomResult",false,"enter a webinar ID first");return;}
  if(!confirm("Join webinar "+idv+"?"))return;
  try{const d=await act("zJoinId",()=>api("/api/zoom/join",{confno:idv},"POST"),"zoomResult","Joining\u2026");res("zoomResult",d.ok,d.detail);refresh();}
  catch(e){res("zoomResult",false,String(e.message||e));}};
function setChips(el,items,cur,fn){
  if(!items||!items.length){
    if(el.children.length===0)el.innerHTML='<span class="mut">none</span>';
    return;  // keep showing the last good list rather than flickering to "none"
  }
  el.innerHTML="";
  items.forEach(x=>{const c=document.createElement("button");c.type="button";c.className="chip"+(x===cur?" cur":"");c.textContent=x;
    c.onclick=()=>{fn(x);};el.appendChild(c);});
}
let adminLoaded=false;
async function loadAdmin(){
  if(adminLoaded)return;
  try{
    const p=await api("/api/profiles");
    if(p.is_admin){
      adminLoaded=true;
      if(p.meetings&&p.meetings.length){
        const box=document.getElementById("profChips");box.innerHTML="";
        document.getElementById("profPick").style.display="block";
        p.meetings.forEach(m=>{
          const c=document.createElement("button");c.type="button";
          c.className="chip"+(m.id===p.active?" cur":"");
          c.textContent=m.name;
          c.onclick=async()=>{try{await api("/api/admin/profile",{id:m.id});res("svcResult",true,"active profile → "+m.name);adminLoaded=false;refresh();}catch(e){res("svcResult",false,String(e.message||e));}};
          box.appendChild(c);});
      }
      try{
        const sc=await api("/api/admin/schedule");
        if(sc.meetings&&sc.meetings.length){
          const el=document.getElementById("schedLine");
          el.textContent="Auto-join (15 min before): "+sc.meetings.map(m=>{
            const d=new Date(m.next_start);
            return m.name+" · "+d.toLocaleDateString(undefined,{weekday:"short"})+" "+m.weekly.time;
          }).join("  ·  ");
        }
      }catch(e){}
    }
  }catch(e){}
}
function refresh(){
  api("/api/state").then(s=>{
    const sn=document.getElementById("scopeName");
    sn.textContent=s.profile_name?("— "+s.profile_name):(s.is_admin?"(admin)":"");
    const dO=document.getElementById("dObs"),dC=document.getElementById("dCam"),dZ=document.getElementById("dZoom");
    dO.className="dot "+(s.obs.connected?"on":"off");
    dC.className="dot "+(s.camera.reachable?"on":"off");
    dZ.className="dot "+(s.zoom.running?"on":"off");
    dO.title=s.obs.connected?("OBS connected"+(s.obs.current?" · scene: "+s.obs.current:"")):"OBS not connected";
    dC.title=s.camera.reachable?"Camera reachable":"Camera unreachable";
    dZ.title=s.zoom.running?("Zoom running"+(s.zoom.account?" · "+s.zoom.account:"")):"Zoom not running";
    document.getElementById("setup").style.display=s.is_admin?"":"none";
    document.getElementById("presetBox").style.display=s.is_admin?"":"none";
    // service buttons: disable whichever is not applicable (don't clobber act()'s busy state)
    const svcA=!!(s.svc&&s.svc.active);
    const svS=document.getElementById("svcStart"), svP=document.getElementById("svcStop");
    if(!svS.disabled)svS.disabled=svcA;
    if(!svP.disabled)svP.disabled=!svcA;
    document.getElementById("wbRow").style.display=(s.is_admin||s.profile_name==="Stake")?"":"none";
    const ar=document.getElementById("activeRow");
    const ss=s.sessions||[];
    ar.style.display="";
    if(s.is_admin){
      const ago=sec=>sec<90?sec+"s ago":sec<5400?Math.round(sec/60)+" min ago":Math.round(sec/3600)+" h ago";
      const dur=sec=>sec<90?sec+"s":sec<5400?Math.round(sec/60)+" min":Math.round(sec/3600)+" h";
      const where=x=>{const w=[x.browser,x.os].filter(Boolean).join(" on ");return w?esc(w):null;} // esc: UA-derived text goes into innerHTML
      const act=ss.filter(x=>x.active);
      let html=act.length
        ?("👥" + ' <b>Currently connected:</b> ' + act.map(x=>x.name+' <span class=\"mut\">(' + ago(x.seconds_ago) + (where(x)?' · '+where(x):'') + ')</span>').join(' · '))
        :'<span class=\"mut\">👥 Nobody connected right now</span>';
      const rest=ss.filter(x=>!x.active).slice(0,4);
      if(rest.length){
        html+='<div class=\"mut\" style=\"margin-top:5px;font-size:12px\">Last seen</div>'
          + rest.map(x=>'<div style=\"font-size:12.5px;padding:2px 0 2px 10px\"><span class=\"mut\">·</span> '+x.name+' <span class=\"mut\">'+ago(x.seconds_ago)+(where(x)?' · '+where(x):'')+' · '+x.visits+(x.visits>1?' sessions':' session')+', '+dur(x.active_seconds)+'</span></div>').join('');
      }
      ar.innerHTML=html;
    }else{
      const act2=ss.filter(x=>x.active);
      ar.innerHTML=act2.length
        ?("👥" + ' <b>Active now:</b> ' + act2.map(x=>x.name).join(' · '))
        :'<span class=\"mut\">👥 Nobody else is active right now</span>';
    }
    setChips(document.getElementById("scenes"),s.obs.scenes,s.obs.current,async x=>{
      try{await api("/api/obs/scene",{name:x});res("obsResult",true,"scene → "+x);refresh();}
      catch(e){res("obsResult",false,String(e.message||e));}});
    const vb=document.getElementById("vcamBtn");if(s.obs.vcam!==null)vb.textContent=s.obs.vcam?"Virtual cam: ON":"Virtual cam: OFF";
    const st=document.getElementById("stream");
    if(s.camera.stream){st.src="/api/camera/stream?token="+encodeURIComponent(T());st.classList.remove("hidden");
      document.getElementById("noStream").classList.add("hidden");}
    else if(!st.dataset.u){st.classList.add("hidden");document.getElementById("noStream").classList.remove("hidden");}
    // Zoom button matrix: each button visible only while it is functional
    //   Sign in : signed OUT | Close : signed IN
    //   Join : signed IN + no meeting | Names : meeting live (Join/Names exclusive)
    // NOTE: buttons are ONLY set from the attendees response (or settled when
    // Zoom is not running) - resetting them on every sync pass raced the
    // in-flight response over the tunnel and caused a visible swap each cycle.
    // Being in a meeting is proof of being signed in, even if a dashboard
    // restart cleared the in-memory account.
    const zst=s.zoom||{};
    const knownAccount=!!zst.account;
    const setVis=(id,show)=>{const e=document.getElementById(id);if(e)e.style.display=show?"":"none";};
    if(!zst.running){
      setVis("zLogin",true);setVis("zClose",false);
      setVis("zJoin",false);setVis("attBtn",false);
      const b=document.getElementById("attBadge");if(b)b.textContent="";
      setVis("zoomHelp",true);
    } else if(!["zLogin","zJoin","zClose"].some(id=>document.getElementById(id).disabled)){
      api("/api/zoom/attendees").then(a=>{
        const inM=a.in_meeting===true;
        const b=document.getElementById("attBadge");
        if(inM){
          b.textContent=a.count!=null?"\u25CF "+a.count+" in meeting":"\u25CF in meeting";
          setVis("zLogin",false);setVis("zClose",true);
          setVis("attBtn",true);setVis("zJoin",false);
          setVis("zoomHelp",false);
        }else{
          b.textContent="";
          setVis("zLogin",!knownAccount);setVis("zClose",knownAccount);
          setVis("zJoin",knownAccount);setVis("attBtn",false);
          setVis("zoomHelp",!knownAccount);
        }
      }).catch(()=>{});
    }
    const za=document.getElementById("zoomAcct");
    if(za)za.textContent=(s.zoom&&s.zoom.account)?"Account: "+s.zoom.account:"";
    netOk();
  }).catch(()=>netBad());
  loadAdmin();
  startPreview();
}
let netFails=0, lastGood=0;
function netOk(){
  netFails=0;lastGood=Date.now();
  const b=document.getElementById("netBanner");if(b)b.classList.add("hidden");
}
function netBad(){
  netFails++;
  const b=document.getElementById("netBanner");
  if(b&&netFails>=2){
    const ago=Math.max(0,Math.round((Date.now()-lastGood)/1000));
    b.innerHTML="⚠ Connection lost — retrying…"+(lastGood?" (last updated "+ago+"s ago)":"");
    b.classList.remove("hidden");
  }
}
setInterval(()=>{
  const u=document.getElementById("updAge");if(!u)return;
  if(!lastGood){u.textContent="";return;}
  const secs=Math.round((Date.now()-lastGood)/1000);
  u.textContent=secs>=5?("stale "+secs+"s"):"";
},1000);
(function(){const el=document.getElementById("presets");
  for(let i=0;i<10;i++){const c=document.createElement("button");c.type="button";c.className="chip";c.textContent=i;
    c.onclick=()=>api("/api/camera/preset",{n:i,save:false}).then(()=>res("camResult",true,"preset "+i)).catch(e=>res("camResult",false,String(e.message||e)));
    el.appendChild(c);} })();
let previewOn=false, wsObj=null, wsGen=0, wsFails=0, pollTimer=null, fpsN=0;
function showFrame(blob){
  const el=document.getElementById("stream");
  const u=URL.createObjectURL(blob);
  if(el.dataset.u)URL.revokeObjectURL(el.dataset.u);
  el.dataset.u=u;el.src=u;el.classList.remove("hidden");
  document.getElementById("noStream").classList.add("hidden");
  fpsN++;
}
function startPoll(){
  if(pollTimer)return;
  pollTimer=true;
  (async()=>{
    while(pollTimer){
      if(!document.hidden){
        try{
          const r=await fetch("/api/obs/preview?w=640",{headers:{Authorization:"Bearer "+T()}});
          if(r.ok){const b=await r.blob();if(b.size>0)showFrame(b);}
        }catch(e){}
      }
      await new Promise(res=>setTimeout(res,150));
    }
  })();
}
function stopPreview(){
  previewOn=false;wsGen++;
  try{if(wsObj)wsObj.close();}catch(e){}
  wsObj=null;pollTimer=null;
}
function connectWs(){
  const gen=++wsGen;
  const el=document.getElementById("stream");
  const w=Math.min(960,Math.max(480,Math.round((el.clientWidth||640)*(window.devicePixelRatio||1))));
  const proto=location.protocol==="https:"?"wss:":"ws:";
  let s;
  try{
    // token goes in the subprotocol list: browsers can't set Authorization
    // on WebSocket, and the Cloudflare WAF strips token-like query params.
    s=new WebSocket(proto+"//"+location.host+"/api/obs/previewws?w="+w+"&fps=25","ct."+T());
  }catch(e){wsFails=99;startPoll();return;}
  wsObj=s;s.binaryType="arraybuffer";
  s.onopen=()=>{wsFails=0;};
  s.onmessage=e=>{if(e.data&&e.data.byteLength>0)showFrame(new Blob([e.data],{type:"image/jpeg"}));};
  s.onclose=()=>{
    if(gen!==wsGen||!previewOn)return;
    wsFails++;
    if(wsFails>=3){wsFails=99;startPoll();}
    else setTimeout(()=>{if(previewOn&&gen===wsGen)connectWs();},500*wsFails);
  };
  s.onerror=()=>{try{s.close();}catch(_){}};
}
function startPreview(){
  if(previewOn||document.hidden)return;
  previewOn=true;
  if(wsFails<3)connectWs();else startPoll();
}
document.addEventListener("visibilitychange",()=>{if(document.hidden)stopPreview();else startPreview();});
document.addEventListener("keydown",e=>{if(e.key==="Escape"){["attModal","credModal"].forEach(id=>{const el=document.getElementById(id);if(el)el.classList.add("hidden");});}});
setInterval(()=>{const b=document.getElementById("fpsBadge");if(b)b.textContent=previewOn?fpsN+" fps":"";fpsN=0;},1000);

if(!T()){gate(true);}else{gate(false);refresh();}
setInterval(refresh,5000);
</script><div id="attModal" class="attmodal hidden" role="dialog" aria-modal="true" aria-label="Participant list" onclick="if(event.target===this)this.classList.add('hidden')">
  <div class="attbox">
    <div class="hd"><b>👥 In the meeting</b>
      <span style="display:flex;gap:8px">
        <button class="btn" style="padding:6px 12px" onclick="showAttendees()">↻</button>
        <button class="btn" style="padding:6px 12px" onclick="document.getElementById('attModal').classList.add('hidden')">✕</button>
      </span>
    </div>
    <div class="bd" id="attBody">Loading…</div>
  </div>
</div>
</body></html>
"""

# ------------------------------------------------- ws preview push (20-30 fps) -
def _next_start(weekly, now):
    """Next occurrence of a weekly {dow, 'HH:MM'} slot (local time) at or after now."""
    hh, mm = (weekly.get("time") or "00:00").split(":")
    t = now.replace(hour=int(hh), minute=int(mm), second=0, microsecond=0)
    days_ahead = (int(weekly.get("dow", 6)) - now.weekday()) % 7
    t += timedelta(days=days_ahead)
    if t < now - timedelta(minutes=20):  # already in the past -> next week
        t += timedelta(days=7)
    return t

# ------------------------------------------------- ws preview push (20-30 fps) -
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

class WSPreview:
    """WebSocket (RFC6455) preview push: server streams binary JPEG frames from
    GetSourceScreenshot at a target fps over ONE persistent connection —
    avoids the per-request tunnel handshake that caps HTTP polling at ~5 fps.
    Modelled on obs-blade's pipelined preview (no idle gap between frames)."""

    def __init__(self, handler, w, fps):
        self.h = handler
        self.sock = handler.connection
        self.w = max(320, min(w, 1920))
        self.fps = max(5, min(fps, 30))
        self.stop = threading.Event()
        self.sendlock = threading.Lock()
        try:
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

    def handshake(self):
        key = self.h.headers.get("Sec-WebSocket-Key", "")
        if not key:
            return False
        # Auth: browsers can't set custom headers on WebSocket, so the token
        # travels in the subprotocol list ("ct.<token>"). The Cloudflare WAF
        # strips token-like query params on this route, so subprotocol is the
        # reliable channel. Query token still accepted if it does arrive.
        proto_hdr = self.h.headers.get("Sec-WebSocket-Protocol", "")
        subproto = proto_hdr.split(",")[0].strip() if proto_hdr else ""
        tok = None
        if subproto.startswith("ct."):
            tok = subproto[3:]
        if not tok:
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.h.path).query)
            if "token" in q:
                tok = q["token"][0]
        if not _token_match(tok or ""):
            log("preview-ws auth fail: proto_present=%s proto_len=%d toklen=%d" % (
                bool(proto_hdr), len(proto_hdr), len(tok or "")))
            self.h._json(401, {"error": "unauthorized"})
            return False
        log("preview-ws auth ok via %s" % ("subprotocol" if subproto.startswith("ct.") else "query"))
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        self.h.send_response(101)
        self.h.send_header("Upgrade", "websocket")
        self.h.send_header("Connection", "Upgrade")
        self.h.send_header("Sec-WebSocket-Accept", accept)
        for t in _all_tokens():
            if subproto == "ct." + t:
                # Echo the subprotocol built from the known token set — never
                # the client's raw header value (CodeQL py/http-response-splitting).
                self.h.send_header("Sec-WebSocket-Protocol", "ct." + t)
                break
        self.h.end_headers()
        try:
            self.sock.settimeout(60)
        except Exception:
            pass
        return True

    def send_frame(self, opcode, payload):
        header = bytearray([0x80 | opcode])
        n = len(payload)
        if n < 126:
            header.append(n)
        elif n < 65536:
            header.append(126)
            header += struct.pack(">H", n)
        else:
            header.append(127)
            header += struct.pack(">Q", n)
        with self.sendlock:
            self.sock.sendall(bytes(header) + payload)

    def _recv(self, buf, n):
        while len(buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("client closed")
            buf += chunk
        return buf

    def read_loop(self):
        """Consume client frames: answer pings, detect close."""
        buf = b""
        while not self.stop.is_set():
            try:
                buf = self._recv(buf, 2)
                b1, b2 = buf[:2]
                buf = buf[2:]
                opcode = b1 & 0x0F
                masked = b2 & 0x80
                ln = b2 & 0x7F
                if ln == 126:
                    buf = self._recv(buf, 2)
                    ln = struct.unpack(">H", buf[:2])[0]
                    buf = buf[2:]
                elif ln == 127:
                    buf = self._recv(buf, 8)
                    ln = struct.unpack(">Q", buf[:8])[0]
                    buf = buf[8:]
                mkey = b""
                if masked:
                    buf = self._recv(buf, 4)
                    mkey = buf[:4]
                    buf = buf[4:]
                if ln:
                    buf = self._recv(buf, ln)
                    payload = buf[:ln]
                    buf = buf[ln:]
                    if masked:
                        payload = bytes(c ^ mkey[i % 4] for i, c in enumerate(payload))
                else:
                    payload = b""
                if opcode == 0x8:
                    self.stop.set()
                    return
                if opcode == 0x9:
                    self.send_frame(0xA, payload[:125])
            except Exception:
                self.stop.set()
                return

    def serve(self):
        threading.Thread(target=self.read_loop, daemon=True).start()
        log("preview-ws: client connected (w=%d fps=%d)" % (self.w, self.fps))
        interval = 1.0 / self.fps
        since_scene = 99
        try:
            while not self.stop.is_set():
                t0 = time.time()
                if since_scene >= 15:
                    since_scene = 0
                    try:
                        cur = OBS.rpc("GetCurrentProgramScene", timeout=5).get("sceneName")
                        if cur:
                            _OBS_CACHE["current"] = cur
                    except Exception:
                        pass
                since_scene += 1
                scene = _OBS_CACHE.get("current")
                if not scene:
                    time.sleep(0.5)
                    continue
                try:
                    d = OBS.rpc("GetSourceScreenshot",
                                {"sourceName": scene, "imageFormat": "jpeg",
                                 "imageWidth": self.w,
                                 "imageCompressionQuality": 75}, timeout=8)
                    raw = d.get("imageData", "")
                    if raw.startswith("data:"):
                        raw = raw.split("base64,", 1)[1]
                    data = base64.b64decode(raw)
                    if data:
                        self.send_frame(0x2, data)
                except Exception as e:
                    log("preview-ws frame error: %s" % str(e)[:120])
                    time.sleep(0.5)
                    continue
                elapsed = time.time() - t0
                if elapsed < interval:
                    # SPIN-WAIT, not time.sleep: this launchd agent's timers
                    # get coalesced/throttled by macOS (measured: sleep(33ms)
                    # took 78-170ms there, capping preview at ~7fps, while a
                    # fresh process sleeps correctly). A 33ms spin costs
                    # ~1% of one core and keeps the frame cadence exact.
                    deadline = t0 + interval
                    while time.time() < deadline:
                        pass
        finally:
            self.stop.set()
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            log("preview-ws: client disconnected")

class Handler(BaseHTTPRequestHandler):
    server_version = "church-dash/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        log("http:", self.address_string(), fmt % args)

    def _token_ok(self):
        tok = CFG.get("token")
        if not tok:
            return False
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return _token_match(auth[7:].strip())
        proto = self.headers.get("Sec-WebSocket-Protocol", "")
        first = proto.split(",")[0].strip() if proto else ""
        if first.startswith("ct."):
            return _token_match(first[3:])
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if "token" in q:
            return _token_match(q["token"][0])
        return False

    def _auth_ok(self, path):
        if path == "/api/gateinfo":
            return True
        if path == "/setup" and not CFG.get("token"):
            return True  # first-run: only /setup may set the token
        ok = self._token_ok()
        if ok:
            _note_session(self._auth_token(), self.headers.get("User-Agent", ""))
        return ok

    def _auth_token(self):
        """Which token value matched this request (Bearer, query, or WS subprotocol)."""
        cand = None
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            cand = auth[7:].strip()
        if cand is None:
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if "token" in q:
                cand = q["token"][0]
        if cand is None:
            proto = self.headers.get("Sec-WebSocket-Protocol", "")
            first = proto.split(",")[0].strip() if proto else ""
            if first.startswith("ct."):
                cand = first[3:]
        if not cand:
            return None
        c = cand.encode("utf-8", "replace")
        for t in _all_tokens():
            try:
                if hmac.compare_digest(c, t.encode("utf-8", "replace")):
                    return t
            except Exception:
                continue
        return None

    def _profile_for(self):
        """Profile id this request is scoped to (token -> profile / admin selection)."""
        entry = _token_entry(self._auth_token())
        return _profile_for_entry(entry)

    def _is_admin(self):
        entry = _token_entry(self._auth_token())
        return bool(entry and entry.get("admin"))

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n)[:1 << 20])
        except Exception:
            return {}

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            body = UI_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store, max-age=0, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/api/gateinfo":
            self._json(200, {"token_set": bool(CFG.get("token"))})
            return
        if not self._auth_ok(path):
            self._json(401, {"error": "unauthorized"})
            return
        if path == "/api/obs/previewws":
            if not (OBS and OBS.connected):
                self._json(503, {"error": "OBS not connected"})
                return
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            try:
                w = int(q.get("w", ["960"])[0])
            except Exception:
                w = 960
            try:
                fps = int(q.get("fps", ["25"])[0])
            except Exception:
                fps = 25
            ws = WSPreview(self, w, fps)
            if not ws.handshake():
                self._json(400, {"error": "bad websocket handshake"})
                return
            ws.serve()
            return
        if path == "/api/zoom/attendees":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            live = q.get("live", ["0"])[0] == "1"
            r = zoom_attendees(live=live)
            self._json(200, r)
            return
        if path == "/api/zoom/participants":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            mid = q.get("id", [""])[0] or None
            # token -> config key (e.g. 'quartz') so we can prefer that account's meeting
            tkey = None
            for k, v in (CFG.get("tokens") or {}).items():
                if (v.get("token") or "") == (self._auth_token() or ""):
                    tkey = k
                    break
            errs = []
            if (CFG.get("zoom_api") or {}).get("client_id"):
                try:
                    r = zoom_api_participants(mid, tkey)
                    self._json(200, r)
                    return
                except Exception as e:
                    errs.append("api: %s" % str(e)[:120])
            try:
                r = zoom_participants()
                if errs:
                    r["warnings"] = errs + (r.get("warnings") or [])
                self._json(200, r)
            except Exception as e:
                self._json(502, {"ok": False, "error": str(e)[:300],
                                 "warnings": errs or None})
            return
        if path == "/api/profiles":
            ms = [{k: m[k] for k in ("id", "name", "email", "confno", "weekly", "scene") if k in m}
                  for m in _meetings()]
            self._json(200, {"is_admin": self._is_admin(),
                             "active": self._profile_for() if self._is_admin() else None,
                             "meetings": ms})
            return
        if path == "/api/admin/schedule":
            if not self._is_admin():
                self._json(403, {"error": "admin token required"})
                return
            now = datetime.now()
            out = []
            for m in _meetings():
                wk = m.get("weekly")
                if not wk:
                    continue
                nxt = _next_start(wk, now)
                out.append({"id": m["id"], "name": m["name"], "weekly": wk,
                            "next_start": nxt.isoformat(timespec="seconds"),
                            "in_minutes": int((nxt - now).total_seconds() // 60)})
            self._json(200, {"now": now.isoformat(timespec="seconds"), "meetings": out,
                             "recent_events": _SCHED.get("events", [])[-10:]})
            return
        if path == "/api/operation":
            with _OP_LOCK:
                self._json(200, dict(_OP))
            return
        if path == "/api/state":
            st = build_state()
            st["is_admin"] = self._is_admin()
            st["profile_id"] = self._profile_for()
            prof = _meeting(st["profile_id"])
            st["profile_name"] = prof.get("name") if prof else None
            if st["is_admin"]:
                st["sessions"] = _session_view(full=True)
            else:
                st["sessions"] = _session_view(full=False, viewer_tok=self._auth_token())
            self._json(200, st)
            return
        if path == "/api/camera/stream":
            if not STREAM_TARGET or CAM is None:
                self._json(503, {"error": "no stream endpoint found"})
                return
            self.proxy_stream()
            return
        if path == "/api/obs/preview":
            if not (OBS and OBS.connected):
                self._json(503, {"error": "OBS not connected"})
                return
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            try:
                w = max(320, min(int(q.get("w", ["640"])[0]), 1920))
            except Exception:
                w = 640
            scene = _OBS_CACHE.get("current")
            if not scene:
                try:
                    scene = OBS.rpc("GetCurrentProgramScene", timeout=5).get("sceneName")
                except Exception:
                    scene = None
            if not scene:
                self._json(500, {"error": "no program scene"})
                return
            try:
                d = OBS.rpc("GetSourceScreenshot",
                            {"sourceName": scene, "imageFormat": "jpeg",
                             "imageWidth": w}, timeout=12)
                raw = d.get("imageData", "")
                if raw.startswith("data:"):
                    raw = raw.split("base64,", 1)[1]
                data = base64.b64decode(raw)
            except Exception as e:
                self._json(502, {"error": str(e)[:150]})
                return
            if not data:
                self._json(502, {"error": "empty screenshot"})
                return
            self.send_response(200)
            self.send_header("Content-Type", "image/jpeg")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)
            return
        if path.startswith("/api/debug/") and not self._is_admin():
            self._json(403, {"error": "debug endpoints require the admin token"})
            return
        if path == "/api/debug/cam":
            # TEMP debug: fetch a camera page with the dashboard's working auth.
            if CAM is None:
                self._json(500, {"error": "camera not configured"})
                return
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            cp = q.get("p", ["/"])[0]
            if not cp.startswith("/"):
                cp = "/" + cp
            try:
                status, body, headers = CAM.get(cp, timeout=10)
            except Exception as e:
                self._json(502, {"error": str(e)[:200]})
                return
            ct = (headers.get("Content-Type") or "").lower()
            is_text = any(t in ct for t in ("text", "json", "javascript", "xml", "html"))
            out = {"status": status, "content_type": ct, "length": len(body),
                   "www_authenticate": headers.get("WWW-Authenticate", "")}
            if is_text:
                out["body"] = body[:300000].decode("utf-8", "replace")
            else:
                out["head_hex"] = body[:16].hex()
                out["body_b64_head"] = base64.b64encode(body[:256]).decode()
            self._json(200, out)
            return
        if path == "/api/debug/ax2":
            # TEMP: is THIS process (dashboard python) AX-trusted?
            import ctypes as _ct
            _appsv = _ct.cdll.LoadLibrary("/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices")
            _appsv.AXIsProcessTrusted.restype = _ct.c_bool
            self._json(200, {"dashboard_trusted": bool(_appsv.AXIsProcessTrusted())})
            return
        if path == "/api/debug/ax":
            # TEMP debug: run zoom_ax in the dashboard's process context
            out = {}
            for arg in (["trusted"], ["dump", "3"], ["names"], ["press", "participants"]):
                r = subprocess.run([_ZAX_BIN] + arg, capture_output=True, text=True, timeout=30)
                out[" ".join(arg)] = {"rc": r.returncode,
                                     "out": (r.stdout or "")[:3000],
                                     "err": (r.stderr or "")[:300]}
            self._json(200, out)
            return
        if path == "/api/debug/keychain":
            out = {}
            for acct in ("zoom-user", "zoom-pass"):
                r = subprocess.run(["security", "find-generic-password", "-s", "church-dash", "-a", acct, "-w"],
                                   capture_output=True, text=True, timeout=5)
                out[acct] = {"rc": r.returncode, "len": len(r.stdout.strip()), "err": r.stderr.strip()[:80]}
            self._json(200, out)
            return

        if path == "/api/debug/zoomui":
            script = r'''
set out to ""
tell application "System Events"
  set pnames to name of every process
  set out to "has_zoomus=" & (pnames contains "zoom.us") & linefeed
  set out to out & "has_Zoom=" & (pnames contains "Zoom") & linefeed
  set procName to ""
  if (pnames contains "zoom.us") then
    set procName to "zoom.us"
  else if (pnames contains "Zoom") then
    set procName to "Zoom"
  end if
  set out to out & "procName=" & procName & linefeed
  if procName is not "" then
    tell process procName
      set out to out & "windows=" & (count of windows) & linefeed
      if (count of windows) > 0 then
        try
          set out to out & "win1=" & (name of window 1) & linefeed
        end try
        try
          set out to out & "buttons=" & (name of every button of window 1 as text) & linefeed
        on error be
          set out to out & "buttons=ERR:" & be & linefeed
        end try
        try
          set out to out & "textfields=" & (name of every text field of window 1 as text) & linefeed
        on error te
          set out to out & "textfields=ERR:" & te & linefeed
        end try
      end if
    end tell
  end if
end tell
return out
'''
            r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=20)
            self._json(200, {"rc": r.returncode, "out": r.stdout.strip()[:1500], "err": r.stderr.strip()[:200]})
            return
        self._json(404, {"error": "not found"})

    def proxy_stream(self):
        host, port, uri = STREAM_TARGET
        url = "http://%s:%s%s" % (host, port, uri)
        base = CAM._base_curl()
        # quick status pre-check (headers arrive first; abort after 2s)
        try:
            chk = subprocess.run(base + ["--max-time", "2", "-o", "/dev/null",
                                        "-w", "%{http_code}", url],
                                 capture_output=True, timeout=8)
            code = (chk.stdout or b"").decode().strip()
        except Exception as e:
            self._json(502, {"error": "stream connect: %s" % str(e)[:120]})
            return
        if code != "200":
            self._json(502, {"error": "camera stream HTTP %s" % code})
            return
        p = None
        try:
            p = subprocess.Popen(base + ["--no-buffer", "-N", url],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            self.send_response(200)
            self.send_header("Content-Type", "multipart/x-mixed-replace")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            while True:
                chunk = p.stdout.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:
            log("stream proxy error:", e)
        finally:
            if p is not None:
                try:
                    p.kill()
                except Exception:
                    pass

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if not self._auth_ok(path):
            self._json(401, {"error": "unauthorized"})
            return
        b = self._body()
        try:
            if path == "/api/debug/osa":
                if not self._is_admin():
                    self._json(403, {"error": "admin token required"})
                    return
                sc = str(b.get("script", ""))
                if not sc or len(sc) > 20000:
                    self._json(400, {"error": "script required (max 20000 chars)"})
                    return
                r = subprocess.run(["osascript", "-e", sc], capture_output=True, text=True, timeout=60)
                self._json(200, {"rc": r.returncode, "out": r.stdout.strip()[:2000], "err": r.stderr.strip()[:300]})
                return

            if path == "/api/screenshot":
                if not self._is_admin():
                    self._json(403, {"error": "admin token required"})
                    return
                out = "/tmp/dash_shot_%d.png" % int(time.time())
                err = None
                data = b""
                try:
                    r = subprocess.run(["screencapture", "-x", out], capture_output=True, text=True, timeout=30)
                    if r.returncode != 0 or not os.path.exists(out):
                        err = r.stderr.strip()[:300] or ("rc=%s" % r.returncode)
                    else:
                        data = open(out, "rb").read()
                        if not data:
                            err = "empty capture"
                except Exception as e:
                    err = str(e)[:300]
                finally:
                    try:
                        os.unlink(out)
                    except OSError:
                        pass
                if err or not data:
                    self._json(500, {"error": "screencapture failed", "err": str(err)})
                    return
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)
                return
            if path == "/setup":
                out = {}
                if not CFG.get("token"):
                    t = b.get("token")
                    if not t or len(t) < 8:
                        self._json(400, {"error": "first setup requires a token of 8+ chars"})
                        return
                    CFG["token"] = t
                    out["token"] = "set"
                if b.get("account") and b.get("zoom_pass"):
                    m = _meeting(str(b["account"]))
                    if not m:
                        self._json(404, {"error": "unknown congregation (must be in congregations.csv)",
                                        "available": [x["name"] for x in _meetings()]})
                        return
                    email = str(b.get("zoom_user") or m.get("email") or "")
                    if not email:
                        self._json(400, {"error": "no email for '%s' (add to CSV or pass zoom_user)" % m["name"]})
                        return
                    zoom_setup(email, str(b["zoom_pass"]), m["name"])
                    out["zoom"] = "stored in Keychain for %s" % m["name"]
                elif b.get("zoom_user") and b.get("zoom_pass"):
                    zoom_setup(str(b["zoom_user"]), str(b["zoom_pass"]), "default")
                    out["zoom"] = "stored in Keychain (account default)"""
                save_config(CFG)
                self._json(200, out)
                return
            if path == "/api/camera/move":
                if CAM is None:
                    self._json(500, {"error": "camera not configured"})
                    return
                a = str(b.get("action", ""))
                allowed = {"up", "down", "left", "right", "leftup", "rightup", "leftdown", "rightdown",
                           "ptzstop", "zoomin", "zoomout", "zoomstop", "focusin", "focusout", "focusstop"}
                if a not in allowed:
                    self._json(400, {"error": "bad action"})
                    return
                parts = ["ptzcmd", a]
                try:
                    spd = int(b.get("speed", 0) or 0)
                except Exception:
                    spd = 0
                spd = max(0, min(100, spd))
                if a in ("zoomin", "zoomout"):
                    # PTZOptics zoom speed scale 1-7; 0 = camera default (fine, as before)
                    parts.append(str(max(1, min(7, round(spd * 7 / 100)))) if spd else "0")
                elif spd and a in ("up", "down", "left", "right", "leftup", "rightup", "leftdown", "rightdown"):
                    # PTZOptics pan speed 1-24, tilt speed 1-20, mapped from 0-100
                    parts.append(str(max(1, min(24, round(spd * 24 / 100)))))
                    parts.append(str(max(1, min(20, round(spd * 20 / 100)))))
                self._json(200, CAM.cmd(*parts))
                return
            if path == "/api/camera/preset":
                if CAM is None:
                    self._json(500, {"error": "camera not configured"})
                    return
                try:
                    n = int(b.get("n"))
                except Exception:
                    self._json(400, {"error": "preset number required"})
                    return
                if not (0 <= n <= 254) or (90 <= n <= 99):
                    self._json(400, {"error": "preset out of range (0-89, 100-254)"})
                    return
                action = "posset" if b.get("save") else "poscall"
                self._json(200, CAM.cmd("ptzcmd", action, n))
                return
            if path == "/api/camera/home":
                if CAM is None:
                    self._json(500, {"error": "camera not configured"})
                    return
                self._json(200, CAM.cmd("ptzcmd", "home"))
                return
            if path == "/api/obs/scene":
                if not (OBS and OBS.connected):
                    self._json(503, {"error": "OBS websocket not connected"})
                    return
                name = b.get("name")
                if not name:
                    self._json(400, {"error": "scene name required"})
                    return
                OBS.rpc("SetCurrentProgramScene", {"sceneName": str(name)})
                self._json(200, {"ok": True, "scene": str(name)})
                return
            if path == "/api/obs/record":
                if not (OBS and OBS.connected):
                    self._json(503, {"error": "OBS websocket not connected"})
                    return
                on = bool(b.get("on"))
                OBS.rpc("StartRecord" if on else "StopRecord")
                self._json(200, {"ok": True, "recording": on})
                return
            if path == "/api/obs/vcam":
                if not (OBS and OBS.connected):
                    self._json(503, {"error": "OBS websocket not connected"})
                    return
                on = bool(b.get("on"))
                try:
                    OBS.rpc("StartVirtualCam" if on else "StopVirtualCam", timeout=5)
                except Exception:
                    OBS.rpc("SetVirtualCamEnabled", {"enabled": on})
                try:
                    vs = OBS.rpc("GetVirtualCamStatus", timeout=5)
                    actual = bool(vs.get("outputActive", vs.get("enabled")))
                except Exception:
                    actual = on
                self._json(200, {"ok": True, "vcam": actual})
                return
            if path == "/api/admin/profile":
                if not self._is_admin():
                    self._json(403, {"error": "admin token required"})
                    return
                pid = str(b.get("id", ""))
                if not _meeting(pid):
                    self._json(404, {"error": "unknown profile",
                                    "available": [m["id"] for m in _meetings()]})
                    return
                global _ACTIVE_PROFILE
                with _PROFILE_LOCK:
                    _ACTIVE_PROFILE = pid
                log("admin: active profile set to %s" % pid)
                self._json(200, {"ok": True, "active": pid})
                return
            if path == "/api/zoom/login":
                m = _meeting(self._profile_for())
                if not m:
                    self._json(404, {"error": "no meeting profile for this token"})
                    return
                r = zoom_login_flow(m["zoom_account"])
                if r["ok"]:
                    _set_last_zoom_account(m["zoom_account"])
                self._json(200 if r["ok"] else 500, r)
                return
            if path == "/api/zoom/join":
                m = _meeting(self._profile_for())
                if not m:
                    self._json(404, {"error": "no meeting profile for this token"})
                    return
                # explicit webinar ID (join on demand) overrides the profile's
                confno = str(b.get("confno") or m.get("confno") or "").strip()
                if not confno:
                    self._json(400, {"error": "no webinar ID: profile has none and none provided"})
                    return
                r = zoom_join(confno, m["zoom_account"],
                             auto_login=bool(b.get("auto_login", True)))
                if r["ok"]:
                    _set_last_zoom_account(m["zoom_account"])
                self._json(200 if r["ok"] else 500, r)
                return
            if path == "/api/zoom/leave":
                r = zoom_leave(force=bool(b.get("force")))
                self._json(200 if r["ok"] else 500, r)
                return
            if path == "/api/zoom/close":
                r = zoom_full_close()
                self._json(200 if r["ok"] else 500, r)
                return
            if path == "/api/zoom/logout":
                r = zoom_logout()
                self._json(200 if r["ok"] else 500, r)
                return
            if path == "/api/zoom/signout":
                r = zoom_signout()
                self._json(200 if r["ok"] else 500, r)
                return
            if path == "/api/service/start":
                self._json(200, svc_start(self._profile_for()))
                return
            if path == "/api/service/stop":
                self._json(200, svc_stop())
                return
            self._json(404, {"error": "not found"})
        except Exception as e:
            log("handler error on", path, ":", e)
            self._json(500, {"error": str(e)[:300]})


# --- self-reloader: SIGHUP re-execs the current script in place (same PID,
#     same GUI session/context). Operator hot-restart without manual relaunch.
def _install_reloader():
    def _h(signum, frame):
        try:
            log("SIGHUP received: re-execing self")
        except Exception:
            pass
        os.execv(sys.executable, [sys.executable] + sys.argv)
    try:
        signal.signal(signal.SIGHUP, _h)
        log("reloader installed (SIGHUP = re-exec self)")
    except Exception as e:
        log("reloader install failed:", e)

# ------------------------------------------------- auto-join scheduler -------
_SCHED = {"events": []}

def scheduler_loop():
    """Every 30s, check each weekly meeting: inside its T-15min window and not
    yet handled -> run the full service start for that profile.
    Skips if a meeting is already in progress (protects back-to-back Sundays)."""
    seen = {}
    while True:
        time.sleep(30)
        try:
            now = datetime.now()
            for m in _meetings():
                wk = m.get("weekly")
                if not wk:
                    continue
                start = _next_start(wk, now)
                delta = (start - now).total_seconds()
                key = "%s|%s" % (m["id"], start.date().isoformat())
                if 0 <= delta <= 900 and key not in seen:
                    seen[key] = True
                    _SCHED["events"].append({"when": now.isoformat(timespec="seconds"),
                                             "profile": m["name"], "status": "triggering"})
                    log("scheduler: T-%.0f min -> auto-join %s" % (delta / 60, m["name"]))
                    try:
                        att = zoom_attendees()
                        if att.get("in_meeting"):
                            log("scheduler: SKIPPED %s - a meeting is already in progress" % m["name"])
                            _SCHED["events"][-1]["status"] = "skipped: meeting in progress"
                            continue
                        r = svc_start(m["id"])
                        _SCHED["events"][-1]["status"] = (
                            "ok" if r.get("ok") else "failed") + " " + json.dumps(r)[:300]
                        log("scheduler: %s -> %s" % (m["name"], json.dumps(r)[:300]))
                    except Exception as e:
                        log("scheduler: %s FAILED: %s" % (m["name"], e))
                        _SCHED["events"][-1]["status"] = "error: %s" % e
                    _SCHED["events"] = _SCHED["events"][-20:]
        except Exception as e:
            log("scheduler tick error:", e)

def main():
    _install_reloader()
    log("starting church-dash on 127.0.0.1:%s" % PORT)
    threading.Thread(target=scheduler_loop, daemon=True).start()
    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    httpd.daemon_threads = True
    def _he(request, client_address):
        import traceback
        log("httpd handler error from %s: %s" % (client_address, traceback.format_exc()[-1200:]))
    httpd.handle_error = _he
    httpd.serve_forever()

if __name__ == "__main__":
    main()
