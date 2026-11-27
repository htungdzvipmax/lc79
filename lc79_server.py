import os
import secrets
import math
import json
import base64
import hashlib
import logging
import random
import threading
import sqlite3
import time
import re
import unicodedata
from collections import deque
from datetime import datetime, timezone, timedelta

import requests
from cryptography.fernet import Fernet
import socketio
from flask import Flask, Response, jsonify, request, send_from_directory

app = Flask(__name__)


@app.route("/bgm.mp3")
def bgm_mp3():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), "bgm.mp3", mimetype="audio/mpeg")

@app.route("/")
def home():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")


@app.route("/dashboard")
def dashboard():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")


@app.route("/logo_lc79.png")
def logo_lc79_png():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), "logo_lc79.png")

@app.route("/logo_lc79.jpg")
def logo_lc79():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), "logo_lc79.jpg")


@app.route("/health")
def health():
    return {"status": "online", "service": "LC79", "dashboard": "/dashboard"}


# Phiên web lưu SQLite để mọi worker Gunicorn đều nhận ra cùng một token.
# Có thể đặt WEB_SESSION_DB=/data/lc79_web_sessions.sqlite3 khi dùng Render Disk.
WEB_SESSION_TTL = 30 * 24 * 3600
_default_session_db = ("/data/lc79_web_sessions.sqlite3"
                       if os.path.isdir("/data") and os.access("/data", os.W_OK)
                       else "/tmp/lc79_web_sessions.sqlite3")
WEB_SESSION_DB = os.environ.get("WEB_SESSION_DB", _default_session_db)
_web_session_db_lock = threading.RLock()


def _session_db():
    folder = os.path.dirname(os.path.abspath(WEB_SESSION_DB))
    os.makedirs(folder, exist_ok=True)
    conn = sqlite3.connect(WEB_SESSION_DB, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("""CREATE TABLE IF NOT EXISTS web_sessions (
        token TEXT PRIMARY KEY, cid TEXT NOT NULL, username TEXT NOT NULL,
        nickname TEXT NOT NULL, access_token TEXT NOT NULL, jwt TEXT NOT NULL,
        balance INTEGER NOT NULL DEFAULT 0, exp REAL NOT NULL, created REAL NOT NULL,
        password_ciphertext TEXT NOT NULL DEFAULT ''
    )""")
    columns = {row[1] for row in conn.execute("PRAGMA table_info(web_sessions)").fetchall()}
    if "password_ciphertext" not in columns:
        conn.execute("ALTER TABLE web_sessions ADD COLUMN password_ciphertext TEXT NOT NULL DEFAULT ''")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_web_sessions_exp ON web_sessions(exp)")
    return conn


def _web_cid(username: str) -> str:
    return "web:" + str(username).strip().lower()


_credential_key_lock = threading.RLock()

def _credential_cipher():
    """Load a stable Fernet key from env or a private file beside the session DB."""
    configured = os.environ.get("WEB_CREDENTIAL_KEY", "").strip()
    if configured:
        key = configured.encode("ascii")
    else:
        key_path = WEB_SESSION_DB + ".credential.key"
        with _credential_key_lock:
            os.makedirs(os.path.dirname(os.path.abspath(key_path)), exist_ok=True)
            try:
                with open(key_path, "rb") as handle:
                    key = handle.read().strip()
            except FileNotFoundError:
                key = Fernet.generate_key()
                fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(key)
            except OSError as exc:
                raise RuntimeError("Không mở được khóa mã hóa credential trên server") from exc
    try:
        return Fernet(key)
    except Exception as exc:
        raise RuntimeError("WEB_CREDENTIAL_KEY không hợp lệ; cần Fernet key chuẩn") from exc

def _encrypt_login_secret(password_md5):
    if not password_md5:
        return ""
    return _credential_cipher().encrypt(str(password_md5).encode("ascii")).decode("ascii")

def _decrypt_login_secret(ciphertext):
    if not ciphertext:
        return ""
    return _credential_cipher().decrypt(str(ciphertext).encode("ascii")).decode("ascii")


def create_web_session(username: str, nickname: str, access_token: str = "", jwt: str = "", balance: int = 0, password_md5: str = "") -> str:
    token = secrets.token_urlsafe(40)
    now = time.time()
    record = {
        "cid": _web_cid(username), "username": str(username),
        "nickname": str(nickname or username), "access_token": str(access_token or ""),
        "jwt": str(jwt or ""), "balance": int(balance or 0), "exp": now + WEB_SESSION_TTL,
        "password_ciphertext": _encrypt_login_secret(password_md5) if password_md5 else "",
    }
    with _web_session_db_lock:
        conn = _session_db()
        try:
            conn.execute("DELETE FROM web_sessions WHERE exp < ?", (now,))
            # Mỗi tài khoản chỉ giữ phiên web mới nhất; tránh token cũ ghi đè credential mới.
            conn.execute("DELETE FROM web_sessions WHERE lower(username)=lower(?)", (record["username"],))
            conn.execute("""INSERT OR REPLACE INTO web_sessions
                (token,cid,username,nickname,access_token,jwt,balance,exp,created,password_ciphertext)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (token, record["cid"], record["username"], record["nickname"],
                 record["access_token"], record["jwt"], record["balance"], record["exp"], now, record["password_ciphertext"]))
            conn.commit()
        finally:
            conn.close()
    return token


def _restore_session_credentials(sess):
    """Nạp lại credential vào state của worker hiện tại nếu request sang worker khác."""
    if not sess or not sess.get("access_token") or not sess.get("jwt"):
        return
    try:
        for table in ("md5", "tx"):
            st = get_state(sess["cid"], table)
            with state_lock:
                st["access_token"] = sess["access_token"]
                st["jwt"] = sess["jwt"]
                st["nickname"] = sess.get("nickname") or sess.get("username")
                if not st.get("balance"):
                    st["balance"] = int(sess.get("balance") or 0)
                    st["initial_balance"] = int(sess.get("balance") or 0)
    except Exception:
        # Không mở quyền nếu không khôi phục được state; request sau sẽ báo lỗi xác thực.
        return


def session_from_request():
    token = (request.headers.get("X-Session-Token") or request.headers.get("X-Dashboard-Token") or "").strip()
    if not token:
        return None
    now = time.time()
    with _web_session_db_lock:
        conn = _session_db()
        try:
            row = conn.execute("SELECT * FROM web_sessions WHERE token=? AND exp>=?", (token, now)).fetchone()
            if row is None:
                conn.execute("DELETE FROM web_sessions WHERE token=? AND exp<?", (token, now))
                conn.commit()
                return None
            sess = dict(row)
            # Sliding expiry: keep remembered login alive while the user keeps returning.
            new_exp = now + WEB_SESSION_TTL
            conn.execute("UPDATE web_sessions SET exp=? WHERE token=?", (new_exp, token))
            conn.commit()
            sess["exp"] = new_exp
        finally:
            conn.close()
    _restore_session_credentials(sess)
    return sess


def dashboard_authorized():
    return session_from_request() is not None


def _dashboard_session_invalid_response():
    """401 chỉ dành cho phiên web nội bộ; không dùng mã này cho JWT LC79."""
    return jsonify({
        "ok": False,
        "error_code": "DASHBOARD_SESSION_INVALID",
        "error": "Phiên web đã hết hạn. Vui lòng đăng nhập lại.",
    }), 401


def _lc79_upstream_error_response(exc):
    """Lỗi xác thực từ LC79 không được biến thành lỗi đăng xuất phiên web."""
    message = str(exc or "Lỗi API LC79")[:220]
    if _is_lc79_session_expired_error(exc):
        return jsonify({
            "ok": False,
            "error_code": "LC79_SESSION_EXPIRED",
            "requires_game_login": True,
            "error": message,
        }), 409
    return jsonify({"ok": False, "error_code": "LC79_API_ERROR", "error": message}), 502


def dashboard_chat_id():
    sess = session_from_request()
    if sess:
        return sess["cid"]
    configured = os.environ.get("DASHBOARD_CHAT_ID", "").strip()
    if configured:
        try:
            return int(configured)
        except ValueError:
            return configured
    ids = list(user_states.keys()) if "user_states" in globals() else []
    return ids[0] if len(ids) == 1 else None


@app.route("/api/dashboard/login", methods=["POST"])
def dashboard_login():
    """Đăng nhập bằng tài khoản LC79 — không cần DASHBOARD_TOKEN."""
    data = request.get_json(silent=True) or {}
    username = str(data.get("username") or data.get("user") or "").strip()
    password = str(data.get("password") or data.get("pass") or "")
    if not username or not password:
        return jsonify({"ok": False, "error": "Nhập tài khoản và mật khẩu LC79"}), 400
    res = login_and_get_token(username, password)
    if "_error" in res:
        return jsonify({"ok": False, "error": res["_error"]}), 401

    cid = _web_cid(username)
    # Dừng phiên cũ của cùng tài khoản web (nếu có)
    try:
        stop_user(cid)
    except Exception:
        pass

    for table in ("md5", "tx"):
        st = get_state(cid, table)
        with state_lock:
            st["balance"] = int(res["money"] or 0)
            st["initial_balance"] = int(res["money"] or 0)
            st["profit"] = 0
            st["access_token"] = res["access"]
            st["jwt"] = res["token"]
            st["nickname"] = res["nickname"]
            st["running"] = False
            st["auto"] = False
            st["ws_connected"] = False
            st["pending"] = None
            st["last_open_sid"] = None
            st["session_id"] = None
            st["engine"] = SessionStore()
            st["bet_log"].clear()
            st["total_win"] = 0
            st["total_lose"] = 0
            st["total_bet"] = 0
            st["win_streak"] = 0
            st["lose_streak"] = 0
            st["mg_step"] = 0
            st["day_bet"] = 0
            st["login_at"] = time.time()
            st["gen"] += 1
            try:
                persist_logs(cid, table, [])
            except Exception:
                pass

    token = create_web_session(username, res.get("nickname") or username, res.get("access"), res.get("token"), res.get("money"), password_md5=md5_hash(password))
    return jsonify({
        "ok": True,
        "token": token,
        "nickname": res.get("nickname") or username,
        "username": username,
        "balance": int(res.get("money") or 0),
        "message": "Đăng nhập LC79 thành công",
    })


@app.route("/api/dashboard/logout", methods=["POST"])
def dashboard_logout():
    token = (
        request.headers.get("X-Session-Token")
        or request.headers.get("X-Dashboard-Token")
        or ""
    ).strip()
    if token:
        with _web_session_db_lock:
            conn = _session_db()
            try:
                conn.execute("DELETE FROM web_sessions WHERE token=?", (token,))
                conn.commit()
            finally:
                conn.close()
    return jsonify({"ok": True, "message": "Đã đăng xuất"})


@app.route("/api/dashboard/status", methods=["GET"])
def dashboard_status():
    if not dashboard_authorized():
        return _dashboard_session_invalid_response()
    cid = dashboard_chat_id()
    if cid is None:
        return jsonify({"error": "Phiên đăng nhập không hợp lệ."}), 400

    cache = globals().setdefault("_dashboard_balance_cache", {})
    now = time.time()
    last = cache.get(cid, 0)
    if now - last > 20:
        st_auth = get_state(cid, "md5")
        if st_auth.get("access_token"):
            refresh_state_balance(st_auth)
            cache[cid] = now

    result = {"server": "online", "chat_id": str(cid), "tables": {}}
    for table in ("md5", "tx"):
        st = get_state(cid, table)
        total = st["total_win"] + st["total_lose"]
        result["tables"][table] = {
            "label": TABLES[table]["label"],
            "connected": bool(st.get("ws_connected")),
            "running": bool(st["running"]),
            "auto": bool(st["auto"]),

            "balance": int(st.get("balance") or 0),
            "initial_balance": int(st.get("initial_balance") or 0),
            "profit": int(st.get("profit") or 0),
            "base_bet": int(st.get("base_bet") or 0),
            "stop_loss": int(st.get("stop_loss") or 0),
            "stop_win": int(st.get("stop_win") or 0),
            "daily_limit": int(st.get("daily_limit") or 0),
            "wins": int(st["total_win"]),
            "losses": int(st["total_lose"]),
            "win_streak": int(st["win_streak"]),
            "lose_streak": int(st["lose_streak"]),
            "accuracy": round(st["engine"].accuracy(), 2),
            "samples": len(st["engine"].perf),
            "history_count": len(st["engine"].recs),
            "backtest_n": 0,
            "backtest_hits": 0,
            "backtest_accuracy": 0.0,
            "backtest_samples": 0,
            "backtest_baseline": 0.0,
            "backtest_edge": 0.0,
            "backtest_coverage": 0.0,
            "algorithm": getattr(st["engine"], "VERSION", "EXTERNAL-API"),
            "algorithm_ready": True,
            "predict_api_configured": True,
            "last_result": st.get("last_result"),
            "recent": list(st["bet_log"])[-30:],
            "pending_reason": (st.get("pending") or {}).get("reason") or "",
            "pending_pred": (st.get("pending") or {}).get("pred"),
            "pending_sid": (st.get("pending") or {}).get("sid"),
            "logged_in": bool(st.get("access_token")),
            "martingale": False,
            "mg_mult": float(st.get("mg_mult") or 2),
            "mg_step": int(st.get("mg_step") or 0),
            "current_bet": int(current_bet(st)),
        }
    # Lịch sử trộn 2 bàn, mới nhất trước
    mixed = []
    for table in ("md5", "tx"):
        st = get_state(cid, table)
        for r in list(st.get("bet_log") or [])[-40:]:
            item = dict(r)
            item["table"] = table
            item["table_label"] = TABLES[table]["label"]
            mixed.append(item)
    mixed.sort(key=lambda x: (str(x.get("time") or ""), str(x.get("sid") or "")), reverse=True)
    result["history"] = mixed[:50]
    # Settings chung lấy từ md5 (đã đồng bộ khi lưu)
    st0 = get_state(cid, "md5")
    result["shared"] = {
        "base_bet": int(st0.get("base_bet") or 1000),
        "mode": "auto",
        "stop_loss": int(st0.get("stop_loss") or 0),
        "stop_win": int(st0.get("stop_win") or 0),
        "daily_limit": int(st0.get("daily_limit") or 0),
        "martingale": False,
        "mg_mult": float(st0.get("mg_mult") or 2),
        "auto_any": any(get_state(cid, t).get("auto") for t in ("md5", "tx")),
    }
    root = user_states.get(cid) or {}
    result["events"] = list(root.get("events") or [])[-15:]
    return jsonify(result)


@app.route("/api/dashboard/control", methods=["POST"])
def dashboard_control():
    if not dashboard_authorized():
        return _dashboard_session_invalid_response()
    cid = dashboard_chat_id()
    if cid is None:
        return jsonify({"error": "Phiên đăng nhập không hợp lệ. Hãy đăng nhập lại."}), 400
    data = request.get_json(silent=True) or {}
    # Mặc định áp dụng cả hai bàn
    # tables: list ["md5","tx"] hoặc table=all/md5/tx
    if isinstance(data.get("tables"), list) and data.get("tables"):
        tables = []
        for t in data["tables"]:
            nt = normalize_table(str(t))
            if nt and nt not in tables:
                tables.append(nt)
    else:
        table_arg = str(data.get("table") or "all").lower()
        tables = ["md5", "tx"] if table_arg in ("all", "both", "2", "") else [normalize_table(table_arg)]
    if not tables or not all(tables):
        return jsonify({"error": "Chọn ít nhất một bàn (MD5 hoặc TX)"}), 400
    action = str(data.get("action", "settings")).lower()

    try:
        params = {}
        for key in ("stop_loss", "stop_win", "daily_limit"):
            if key in data:
                params[{"stop_loss": "sl", "stop_win": "sw", "daily_limit": "limit"}[key]] = str(data[key] or "0")
        amount = data.get("base_bet")
        mg_mult = data.get("mg_mult")
        messages = []
        for table in tables:
            st = get_state(cid, table)
            if amount is not None:
                value = parse_amount(str(amount))
                if value <= 0:
                    raise ValueError("Mức cược phải lớn hơn 0")
                st["base_bet"] = value
            if mg_mult is not None:
                try:
                    st["mg_mult"] = max(1.5, min(3.0, float(mg_mult)))
                except (TypeError, ValueError):
                    st["mg_mult"] = 2.0
            if action == "start":
                ok, message = _set_auto(cid, table, True, str(st["base_bet"]), params)
                if not ok:
                    return jsonify({"ok": False, "message": f"{TABLES[table]['label']}: {message}"}), 409
                messages.append(message)
            elif action == "stop":
                _apply_auto_settings(st, params)
                ok, message = _set_auto(cid, table, False)
                messages.append(message)
            elif action == "settings":
                _apply_auto_settings(st, params)
                messages.append(f"Đã lưu {TABLES[table]['label']}")
            elif action == "baseline":
                current = refresh_state_balance(st)
                if current is None:
                    return jsonify({"ok": False, "message": "Không đọc được số dư thật để đặt mốc vốn."}), 409
                for table_key in ("md5", "tx"):
                    other = get_state(cid, table_key)
                    other["initial_balance"] = int(current)
                    other["profit"] = 0
                messages.append("Đã đặt mốc vốn theo số dư hiện tại")
                break
            else:
                return jsonify({"error": "action must be start, stop, settings or baseline"}), 400
        return jsonify({"ok": True, "message": " · ".join(messages)})
    except (ValueError, TypeError) as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    except Exception as exc:
        log.exception("dashboard_control failed")
        return jsonify({"ok": False, "message": f"Lỗi server: {exc}"}), 500


@app.route("/api/dashboard/export.txt", methods=["GET"])
def dashboard_export():
    if not dashboard_authorized():
        return _dashboard_session_invalid_response()
    cid = dashboard_chat_id()
    if cid is None:
        return jsonify({"error": "Phiên đăng nhập không hợp lệ. Hãy đăng nhập lại."}), 400
    table_arg = request.args.get("table", "all")
    tables = ["md5", "tx"] if table_arg == "all" else [normalize_table(table_arg)]
    if not all(tables):
        return jsonify({"error": "table must be md5, tx or all"}), 400
    chunks = ["LC79 - LICH SU DU DOAN VA CUOC", f"Xuat luc: {vn_now().isoformat()}", ""]
    for table in tables:
        st = get_state(cid, table)
        chunks.append(f"===== {TABLES[table]['label']} =====")
        chunks.append(format_history_txt(list(st["bet_log"]), table))
        chunks.append("")
    payload = "\n".join(chunks).encode("utf-8")
    return Response(payload, mimetype="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="lc79_history_{table_arg}.txt"'})




# ============================================================
# LC79 PROFILE / GAME ACTIVITY / WALLET PROXY
# Các API này chỉ chạy ở backend để tránh CORS và không đưa JWT ra trình duyệt.
# ============================================================
LC79_ORIGIN = "https://play.lc79.bet"
LC79_HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7.8 Mobile/15E148 Safari/604.1",
    "Origin": LC79_ORIGIN,
    "Referer": LC79_ORIGIN + "/",
}
LC79_WLB = "https://wlb.tele68.com"
LC79_GAMEAPI = "https://gameapi.tele68.com"


def _lc79_credentials(cid=None):
    cid = cid or dashboard_chat_id()
    if cid is None:
        raise RuntimeError("Phiên đăng nhập không hợp lệ")
    st = get_state(cid, "md5")
    jwt = str(st.get("jwt") or "").strip()
    access = str(st.get("access_token") or "").strip()
    if not jwt or not access:
        raise RuntimeError("Thiếu phiên xác thực LC79. Vui lòng đăng nhập lại")
    return cid, st, jwt, access


_jwt_refresh_guard = threading.RLock()
_jwt_refresh_locks = {}
_jwt_refresh_cache = {}


def _api_payload_auth_expired(status_code, data):
    """Nhận diện cả HTTP 401 lẫn API trả code 401 trong HTTP 200."""
    if int(status_code or 0) in (401, 419):
        return True
    auth_codes = {"401", "419", "UNAUTHORIZED", "TOKEN_EXPIRED", "AUTH_EXPIRED", "JWT_EXPIRED"}
    auth_words = (
        "token expired", "jwt expired", "session expired", "unauthorized",
        "invalid token", "token invalid", "phiên game hết hạn", "phiên đăng nhập hết hạn",
        "hết phiên đăng nhập", "access token expired",
    )
    stack = [data]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, value in item.items():
                k = str(key).lower()
                if k in ("code", "status", "errorcode", "error_code") and str(value).upper() in auth_codes:
                    return True
                if k in ("message", "msg", "error", "detail") and any(w in str(value).lower() for w in auth_words):
                    return True
                if isinstance(value, (dict, list)):
                    stack.append(value)
        elif isinstance(item, list):
            stack.extend(item)
    return False


def _extract_lobby_jwt(raw):
    if not isinstance(raw, dict):
        return ""
    body = _unwrap_dict(raw)
    token = body.get("token") or body.get("jwt") or body.get("accessToken")
    if not token:
        token = raw.get("token") or raw.get("jwt")
    return str(token or "").strip()


def _refresh_lc79_jwt(old_jwt):
    """Re-login through both provider auth steps and atomically rotate shared session credentials."""
    now = time.time()
    old_key = str(old_jwt or "")
    cached = _jwt_refresh_cache.get(old_key)
    if cached and cached[1] > now:
        _sync_refreshed_state(cached[4], cached[3], cached[2], cached[0])
        return cached[0]

    with _jwt_refresh_guard:
        lock = _jwt_refresh_locks.setdefault(old_key, threading.RLock())
    with lock:
        now = time.time()
        cached = _jwt_refresh_cache.get(old_key)
        if cached and cached[1] > now:
            _sync_refreshed_state(cached[4], cached[3], cached[2], cached[0])
            return cached[0]

        conn = _session_db()
        try:
            row = conn.execute(
                "SELECT token,cid,username,nickname,access_token,jwt,password_ciphertext FROM web_sessions WHERE jwt=? AND exp>=? LIMIT 1",
                (old_key, now),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            raise RuntimeError("Phiên web không còn credential để cấp lại JWT")

        username = str(row["username"] or "").strip()
        nickname = str(row["nickname"] or username).strip()
        access = str(row["access_token"] or "").strip()
        password_md5 = ""
        if row["password_ciphertext"]:
            try:
                password_md5 = _decrypt_login_secret(row["password_ciphertext"])
            except Exception:
                log.warning("Không giải mã được credential re-login %s; giữ phiên an toàn", "LC79")

        new_access, new_nickname, new_jwt = "", nickname, ""
        # Prefer a fresh first-step AccessToken, not the expired AccessToken previously in DB.
        if password_md5:
            first = requests.get(
                "https://apifo88daigia.tele68.com/api",
                params={"c": "3", "un": username, "pw": password_md5, "cp": "R", "cl": "R", "pf": "web", "at": ""},
                headers=dict(LC79_HEADERS), timeout=18,
            )
            try:
                first_raw = first.json()
            except ValueError:
                first_raw = {"message": (first.text or "")[:160]}
            if first.status_code >= 400 or not isinstance(first_raw, dict) or first_raw.get("success") is not True:
                detail = _safe_upstream_message(first_raw) or f"LC79 login-step-1 HTTP {first.status_code}"
                raise RuntimeError(f"Không cấp lại được AccessToken: {detail}")
            new_access = str(first_raw.get("accessToken") or "").strip()
            session_key = str(first_raw.get("sessionKey") or "").strip()
            if not new_access or not session_key:
                raise RuntimeError("API login-step-1 thiếu AccessToken hoặc sessionKey")
            new_nickname = _lc79_decode_nickname(session_key, first_raw, username)
        else:
            # Compatibility for sessions created before encrypted re-login was introduced.
            new_access = access

        if not new_access or not new_nickname:
            raise RuntimeError("Không có AccessToken/nickname để làm mới JWT")
        response = requests.post(
            "https://wlb.tele68.com/v1/lobby/auth/login",
            params={"cp": "R", "cl": "R", "pf": "web", "at": ""},
            headers=dict(LC79_HEADERS),
            json={"nickName": new_nickname, "accessToken": new_access}, timeout=18,
        )
        try:
            raw = response.json()
        except ValueError:
            raw = {"message": (response.text or "")[:160]}
        if response.status_code >= 400 or _api_payload_auth_expired(response.status_code, raw):
            detail = _safe_upstream_message(raw) or f"lobby/auth/login HTTP {response.status_code}"
            raise RuntimeError(f"Lobby không cấp JWT mới: {detail}")
        if isinstance(raw, dict) and raw.get("success") is False:
            raise RuntimeError(_safe_upstream_message(raw) or "Lobby từ chối cấp JWT")
        new_jwt = _extract_lobby_jwt(raw)
        if not new_jwt:
            raise RuntimeError("Lobby response không có trường token/JWT")

        conn = _session_db()
        try:
            conn.execute(
                "UPDATE web_sessions SET access_token=?,nickname=?,jwt=? WHERE token=? AND jwt=?",
                (new_access, new_nickname, new_jwt, row["token"], old_key),
            )
            conn.commit()
        finally:
            conn.close()
        _sync_refreshed_state(row["cid"], new_nickname, new_access, new_jwt)
        _jwt_refresh_cache[old_key] = (new_jwt, time.time() + 180, new_access, new_nickname, row["cid"])
        if len(_jwt_refresh_cache) > 128:
            for key, value in list(_jwt_refresh_cache.items()):
                if value[1] <= time.time():
                    _jwt_refresh_cache.pop(key, None)
        return new_jwt


def _sync_refreshed_state(cid, nickname, access, jwt):
    if cid is None or "state_lock" not in globals() or "get_state" not in globals():
        return
    try:
        for table in ("md5", "tx"):
            st = get_state(cid, table)
            with state_lock:
                st["access_token"] = access
                st["jwt"] = jwt
                st["nickname"] = nickname
    except Exception:
        pass


def _safe_upstream_message(data):
    """Return a short provider message without leaking bearer/access/session credentials."""
    candidates = []
    stack = [data]
    while stack:
        item = stack.pop(0)
        if isinstance(item, dict):
            for key in ("message", "msg", "error_description", "detail", "error"):
                value = item.get(key)
                if isinstance(value, (str, int, float)) and str(value).strip():
                    candidates.append(str(value).strip())
            for value in item.values():
                if isinstance(value, (dict, list)):
                    stack.append(value)
        elif isinstance(item, list):
            stack.extend(item)
    message = candidates[0] if candidates else ""
    message = re.sub(r"(?i)(access[_-]?token|refresh[_-]?token|session[_-]?key|authorization|jwt|token)\s*[:=]\s*[^,;\s]+", r"\1=[đã ẩn]", message)
    message = re.sub(r"Bearer\s+[^\s,;]+", "Bearer [đã ẩn]", message, flags=re.I)
    return message[:180]


def _lc79_request(method, url, jwt, *, params=None, payload=None, timeout=15, retry_auth=True):
    """Call provider API with both query at=JWT and Authorization: Bearer JWT.

    A 401 is retried once after rotating the JWT through lobby/auth/login.
    Upstream errors include the endpoint path and safe response message; credentials
    are never returned to the browser or written to logs.
    """
    base_query = {"cp": "R", "cl": "R", "pf": "web", "at": str(jwt or "")}
    if params:
        base_query.update(params)
    endpoint_path = requests.utils.urlparse(url).path or "/"

    def perform(token):
        query = dict(base_query)
        query["at"] = token
        headers = dict(LC79_HEADERS)
        headers["Authorization"] = f"Bearer {token}"
        response = requests.request(
            method.upper(), url, params=query, json=payload,
            headers=headers, timeout=timeout,
        )
        try:
            body = response.json()
        except ValueError:
            body = {"message": (response.text or "")[:300]}
        return response, body

    active_jwt = str(jwt or "")
    response, data = perform(active_jwt)
    if _api_payload_auth_expired(response.status_code, data):
        if retry_auth:
            try:
                active_jwt = _refresh_lc79_jwt(active_jwt)
                response, data = perform(active_jwt)
            except Exception as refresh_exc:
                refresh_message = _safe_upstream_message({"message": str(refresh_exc)})
                raise RuntimeError(
                    f"LC79 từ chối JWT tại {endpoint_path} (HTTP {response.status_code}); "
                    f"không làm mới được phiên lobby: {refresh_message or 'AccessToken đã hết hạn'}. "
                    "Vui lòng đăng nhập lại tài khoản game."
                )
        if _api_payload_auth_expired(response.status_code, data):
            detail = _safe_upstream_message(data)
            suffix = f" Phản hồi: {detail}" if detail else ""
            raise RuntimeError(
                f"LC79 từ chối JWT mới tại {endpoint_path} (HTTP {response.status_code}).{suffix} "
                "Kiểm tra phiên game hoặc đăng nhập lại."
            )

    if response.status_code >= 400:
        detail = _safe_upstream_message(data)
        suffix = f" Phản hồi: {detail}" if detail else ""
        raise RuntimeError(f"API LC79 {endpoint_path} trả HTTP {response.status_code}.{suffix}")

    # Some versions return application errors inside HTTP 200 JSON.
    body_error = _lc79_body_error(data)
    if body_error:
        safe_error = _safe_upstream_message({"message": body_error}) or body_error[:180]
        raise RuntimeError(f"API LC79 {endpoint_path} từ chối yêu cầu: {safe_error}")
    return data


def _is_lc79_session_expired_error(exc):
    message = str(exc or "").lower()
    return any(part in message for part in (
        "phiên truy cập lc79 đã hết hạn",
        "lc79 vẫn từ chối phiên mới",
        "access token lc79 không còn hiệu lực",
        "không thể làm mới phiên lc79",
        "phiên đăng nhập lc79 đã bị ngắt",
        "lc79 từ chối token",
        "lc79 từ chối jwt",
        "không làm mới được phiên lobby",
        "access token đã hết hạn",
    ))


def _unwrap_dict(data):
    cur = data
    for _ in range(4):
        if not isinstance(cur, dict):
            break
        nested = None
        for key in ("data", "result", "profile", "user", "account"):
            if isinstance(cur.get(key), dict):
                nested = cur[key]
                break
        if nested is None:
            break
        cur = nested
    return cur if isinstance(cur, dict) else {}


def _unwrap_list(data):
    """Nhận mảng dù API bọc trong data/list/result/bankList nhiều lớp."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # Object đơn lẻ đã là 1 ngân hàng
        keys = {str(k).replace("_", "").lower() for k in data.keys()}
        if {"bankcode", "accountnumber", "accountname"} & keys or (
            {"type", "number", "name"} <= keys
        ):
            return [data]
        aliases = {"data", "list", "items", "records", "banks", "banklist", "bank_list",
                   "listbank", "rows", "accounts", "bankaccounts", "paymentinfo", "result"}
        for key, value in data.items():
            if str(key).replace("-", "_").lower() in aliases:
                if isinstance(value, list):
                    return value
                if isinstance(value, dict):
                    found = _unwrap_list(value)
                    if found:
                        return found
        for value in data.values():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                return value
            if isinstance(value, dict):
                found = _unwrap_list(value)
                if found:
                    return found
    return []


def _bank_value(bank, names):
    if not isinstance(bank, dict):
        return ""
    lowered = {str(k).replace("_", "").lower(): v for k, v in bank.items()}
    for name in names:
        value = lowered.get(str(name).replace("_", "").lower())
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _bank_shape(obj, depth=0):
    """Mô tả cấu trúc JSON (kiểu + tên key), KHÔNG in giá trị — tránh lộ số tài khoản trong log."""
    if depth > 4:
        return "..."
    if isinstance(obj, dict):
        return {str(k): _bank_shape(v, depth + 1) for k, v in list(obj.items())[:12]}
    if isinstance(obj, list):
        return {"list_len": len(obj), "item": _bank_shape(obj[0], depth + 1) if obj else None}
    return type(obj).__name__


def _normalize_linked_banks(raw):
    """Bóc tách danh sách tài khoản ngân hàng đã liên kết, chịu được mọi kiểu bọc JSON."""
    BANK_KEYS = {"bankcode", "accountnumber", "accountname", "bankname", "receiver", "number",
                 "accountno", "cardnumber", "ownername", "fullname", "short", "bank", "type"}

    def norm_item(item):
        return {str(k).lower().replace("_", ""): v for k, v in item.items()}

    def is_bank_dict(item):
        if not isinstance(item, dict):
            return False
        keys = {str(k).lower().replace("_", "") for k in item.keys()}
        return len(keys & BANK_KEYS) >= 2

    def find_list(obj, depth=0):
        if depth > 8:
            return None
        if isinstance(obj, list):
            dicts = [x for x in obj if isinstance(x, dict)]
            if dicts and any(is_bank_dict(x) for x in dicts):
                return dicts
            for x in obj:
                r = find_list(x, depth + 1)
                if r:
                    return r
        elif isinstance(obj, dict):
            for v in obj.values():
                r = find_list(v, depth + 1)
                if r:
                    return r
        return None

    bank_list = find_list(raw)
    if not bank_list:
        # Dự phòng: mảng dict nào có một chuỗi số dài (số tài khoản) thì coi là danh sách NH
        def find_fallback(obj, depth=0):
            if depth > 8:
                return None
            if isinstance(obj, list):
                dicts = [x for x in obj if isinstance(x, dict)]
                if dicts and any(
                    any(isinstance(v, (str, int)) and len(str(v)) >= 6 and str(v).isdigit() for v in x.values())
                    for x in dicts
                ):
                    return dicts
                for x in obj:
                    r = find_fallback(x, depth + 1)
                    if r:
                        return r
            elif isinstance(obj, dict):
                for v in obj.values():
                    r = find_fallback(v, depth + 1)
                    if r:
                        return r
            return None
        bank_list = find_fallback(raw)
    if not bank_list:
        return []

    result = []
    for raw_index, item in enumerate(bank_list):
        it = norm_item(item)
        code = it.get("bankcode") or it.get("bankname") or it.get("bank") or it.get("type") or it.get("code")
        number = (it.get("accountnumber") or it.get("accountno") or it.get("number")
                  or it.get("receiver") or it.get("cardnumber"))
        owner = (it.get("accountname") or it.get("ownername") or it.get("fullname")
                 or it.get("name"))
        title = it.get("short") or it.get("bankname") or code
        if code and number and owner:
            result.append({
                "index": raw_index,
                "bankCode": str(code),
                "accountNumber": str(number),
                "accountName": str(owner),
                "bankName": str(title),
            })
    return result



def _find_nested_value(data, key_names):
    wanted = {str(k).lower() for k in key_names}
    stack = [data]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, value in item.items():
                if str(key).lower() in wanted:
                    return value
                if isinstance(value, (dict, list)):
                    stack.append(value)
        elif isinstance(item, list):
            stack.extend(item)
    return None


def _parse_int_money(value, default=0):
    try:
        if isinstance(value, str):
            value = value.replace(",", "").replace(".", "").strip()
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _get_profile_and_security(jwt):
    profile_raw = _lc79_request(
        "GET", LC79_WLB + "/v1/minigame/user/detail-info", jwt
    )
    security_raw = _lc79_request(
        "GET", LC79_WLB + "/v1/minigame/user/security-info", jwt
    )
    profile = _unwrap_dict(profile_raw)
    security = _unwrap_dict(security_raw)
    return profile, security


@app.route("/api/dashboard/keepalive", methods=["GET"])
def dashboard_keepalive():
    """Ping detail-info định kỳ; không tự login đè lên thiết bị khác."""
    if not dashboard_authorized():
        return _dashboard_session_invalid_response()
    try:
        cid, st, jwt, access = _lc79_credentials()
        body = _lc79_request("GET", ACCOUNT_URL, jwt, timeout=12, retry_auth=True)
        body_data = _unwrap_dict(body)
        balance = _parse_int_money(_find_nested_value(body_data, ("balance", "money", "availableBalance")), None)
        if balance is not None:
            with state_lock:
                apply_shared_balance(st, balance)
        return jsonify({"ok": True, "alive": True, "balance": balance})
    except Exception as exc:
        msg = str(exc)[:220]
        log.warning("LC79 keepalive failed: %s", msg)
        # Không tự đăng nhập lại ở đây: nếu phiên bị kick do thiết bị khác,
        # auto-login liên tục sẽ tạo vòng đá phiên giữa các thiết bị.
        return jsonify({"ok": False, "alive": False, "error": msg, "reason": "lc79_session"}), 409


@app.route("/api/dashboard/profile", methods=["GET"])
def dashboard_profile():
    if not dashboard_authorized():
        return _dashboard_session_invalid_response()
    try:
        cid, st, jwt, access = _lc79_credentials()
        profile, security = _get_profile_and_security(jwt)
        balance = _parse_int_money(profile.get("balance"), None)
        if balance is not None:
            with state_lock:
                apply_shared_balance(st, balance)
        return jsonify({
            "ok": True,
            "profile": {
                "user_name": profile.get("user_name") or "",
                "nick_name": profile.get("nick_name") or st.get("nickname") or "",
                "balance": balance if balance is not None else int(st.get("balance") or 0),
                "safe": _parse_int_money(profile.get("safe"), 0),
                "mobilePhone": profile.get("mobilePhone") or "",
                "mobile": profile.get("mobile") or "",
            },
            "security": {
                "mobileSecure": int(security.get("mobileSecure") or 0),
                "telegramSecure": int(security.get("telegramSecure") or 0),
                "mobilePhone": security.get("mobilePhone") or profile.get("mobilePhone") or "",
                "telegramAccount": security.get("telegramAccount") or "",
                "otpPriority": security.get("otpPriority") or "",
            },
        })
    except Exception as exc:
        log.warning("Profile LC79 lỗi: %s", str(exc)[:160])
        return _lc79_upstream_error_response(exc)


@app.route("/api/dashboard/activity", methods=["GET"])
def dashboard_activity():
    if not dashboard_authorized():
        return _dashboard_session_invalid_response()
    try:
        _cid, _st, jwt, _access = _lc79_credentials()
        limit = max(1, min(_parse_int_money(request.args.get("limit"), 20), 50))
        params = {"limit": limit}
        before_id = str(request.args.get("beforeId") or "").strip()
        if before_id:
            params["beforeId"] = before_id
        raw = _lc79_request(
            "GET", LC79_WLB + "/v1/lobby/activity/history", jwt, params=params
        )
        rows = _unwrap_list(raw)
        next_cursor = str(rows[-1].get("_id") or "") if rows and isinstance(rows[-1], dict) else ""
        latest_balance = None
        if rows and isinstance(rows[0], dict):
            latest_balance = _parse_int_money(rows[0].get("current_money"), None)
            if latest_balance is not None:
                with state_lock:
                    apply_shared_balance(_st, latest_balance)
        return jsonify({"ok": True, "items": rows, "next_before_id": next_cursor,
                        "current_balance": latest_balance,
                        "has_more": len(rows) >= limit})
    except Exception as exc:
        log.warning("Activity LC79 lỗi: %s", str(exc)[:160])
        return _lc79_upstream_error_response(exc)


@app.route("/api/dashboard/banks", methods=["GET"])
def dashboard_banks():
    if not dashboard_authorized():
        return _dashboard_session_invalid_response()
    try:
        _cid, _st, jwt, _access = _lc79_credentials()
        raw = _lc79_request(
            "GET", LC79_WLB + "/v1/lobby/payment-info/list-bank/cashout", jwt
        )
        if isinstance(raw, dict):
            code = raw.get("code")
            explicit_fail = raw.get("success") is False
            bad_code = str(code).upper() in {"401", "419", "UNAUTHORIZED", "ERROR", "FAIL", "FAILED"}
            if explicit_fail or bad_code:
                raise RuntimeError(str(raw.get("message") or "Không tải được ngân hàng đã liên kết")[:180])
        safe_banks = _normalize_linked_banks(raw)
        log.info("Bank API shape=%s parsed=%s", _bank_shape(raw), len(safe_banks))
        return jsonify({"ok": True, "banks": safe_banks})
    except Exception as exc:
        log.warning("Bank list LC79 lỗi: %s", str(exc)[:160])
        return _lc79_upstream_error_response(exc)



@app.route("/api/dashboard/deposit", methods=["POST"])
def dashboard_deposit():
    if not dashboard_authorized():
        return _dashboard_session_invalid_response()
    data = request.get_json(silent=True) or {}
    amount = _parse_int_money(data.get("amount"), 0)
    if amount <= 0:
        return jsonify({"error": "Số tiền nạp phải lớn hơn 0"}), 400
    try:
        _cid, _st, jwt, _access = _lc79_credentials()
        raw = _lc79_request(
            "GET", LC79_GAMEAPI + "/v1/payment-app/cash-in/bank", jwt,
            params={"amount": amount},
        )
        body = raw if isinstance(raw, dict) else {}
        info = body.get("data") if isinstance(body.get("data"), dict) else _unwrap_dict(body)
        deposit_ok = body.get("code") in (0, "0") or body.get("success") is True or body.get("message") == "success"
        if not deposit_ok:
            return jsonify({"error": str(body.get("message") or "Không tạo được lệnh nạp")[:220]}), 502
        qr = info.get("qr") or ""
        if isinstance(qr, str) and qr and not qr.startswith("data:"):
            qr = "data:image/png;base64," + qr.split(",")[-1]
        return jsonify({"ok": True, "deposit": {
            "amount": amount, "bank": info.get("type") or "",
            "account_name": info.get("name") or "",
            "message": info.get("msg") or "", "qr": qr,
            "url": info.get("url") or "", "expired": _parse_int_money(info.get("expired"), 300),
        }})
    except Exception as exc:
        log.warning("Cash-in LC79 lỗi: %s", str(exc)[:160])
        return _lc79_upstream_error_response(exc)



def run_web():
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)


# =========================
# CẤU HÌNH
# =========================
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger("lc79")
logging.getLogger("engineio").setLevel(logging.WARNING)
logging.getLogger("socketio").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

# Web-only runtime

# Hai bàn độc lập: Tài/Xỉu MD5 và Tài/Xỉu thường.
# Từng bàn có API lịch sử + WebSocket + engine + trạng thái Auto riêng.
TABLES = {
    "md5": {
        "key": "txmd5", "label": "TÀI XỈU MD5",
        "history": os.environ.get("LC79_MD5_HISTORY_API_URL", "https://wtxmd52.tele68.com/v1/txmd5/sessions"),
        "fallback": os.environ.get("LC79_MD5_HISTORY_API_FALLBACK", "https://living-telecommunications-start-consoles.trycloudflare.com/api/txmd5"),
        "ws_url": os.environ.get("LC79_MD5_WS_URL", "https://wtxmd52.tele68.com"),
        "ws_path": os.environ.get("LC79_MD5_WS_PATH", "txmd5/"),
        "namespace": os.environ.get("LC79_MD5_WS_NAMESPACE", "/txmd5"),
        "origin": os.environ.get("LC79_MD5_WS_ORIGIN", "https://lc79b.bet"),
    },
    "tx": {
        "key": "tx", "label": "TÀI XỈU THƯỜNG",
        "history": os.environ.get("LC79_TX_HISTORY_API_URL", "https://wtx.tele68.com/v1/tx/sessions"),
        "fallback": os.environ.get("LC79_TX_HISTORY_API_FALLBACK", ""),
        "ws_url": os.environ.get("LC79_TX_WS_URL", "https://wtx.tele68.com"),
        "ws_path": os.environ.get("LC79_TX_WS_PATH", "tx/"),
        "namespace": os.environ.get("LC79_TX_WS_NAMESPACE", "/tx"),
        "origin": os.environ.get("LC79_TX_WS_ORIGIN", "https://lc79c.vin"),
    },
}
DEFAULT_TABLE = "md5"
MAX_HISTORY = max(100, min(int(os.environ.get("LC79_MAX_HISTORY", "10000")), 30000))
SYNC_INTERVAL = max(5, int(os.environ.get("LC79_SYNC_INTERVAL", "15")))

ACCOUNT_URL = "https://wlb.tele68.com/v1/minigame/user/detail-info"

# Tỷ lệ trả thưởng tham chiếu (chỉ dùng log/hiển thị).
WIN_PROFIT = 1.98
LOSE_LOSS = 1.0

TAI, XIU = "TAI", "XIU"

# API dự đoán ngoài theo bàn (không nạp phiên nội bộ để dự đoán).
# TX thường / hũ TX:
PREDICT_API_TX = os.environ.get("PREDICT_API_TX", "https://kftxiphcytt.onrender.com/lc79/tx").strip()
# TX MD5:
PREDICT_API_MD5 = os.environ.get("PREDICT_API_MD5", "https://kftxiphcytt.onrender.com/lc79/md5").strip()
PREDICT_TIMEOUT = max(3, min(int(os.environ.get("PREDICT_TIMEOUT", "8")), 20))

def predict_url_for(table):
    table = normalize_table(table) or DEFAULT_TABLE
    if table == "tx":
        return PREDICT_API_TX
    return PREDICT_API_MD5

state_lock = threading.RLock()
active_sockets = {}  # khóa (chat_id, table_key)
user_states = {}


# ============================================================
# LOG + SỰ KIỆN THÔNG BÁO WEB
# ============================================================
def push_event(cid, title, body="", kind="info"):
    try:
        root = user_states.get(cid)
        if root is None:
            return
        events = root.setdefault("events", [])
        events.append({
            "id": f"{time.time():.0f}-{len(events)}",
            "ts": time.time(),
            "title": str(title)[:80],
            "body": str(body)[:160],
            "kind": kind,
        })
        if len(events) > 30:
            del events[:-30]
    except Exception:
        pass


# ============================================================
# TIỆN ÍCH
# ============================================================
VN_TZ = timezone(timedelta(hours=7))


def vn_now():
    return datetime.now(VN_TZ)


def sid_sort_key(value):
    text = str(value)
    try:
        return (0, int(text))
    except (TypeError, ValueError):
        return (1, text)


def normalize_sid(value):
    text = str(value).strip()
    try:
        return int(text)
    except (TypeError, ValueError):
        return text


def norm(s):
    s = s.replace("đ", "d").replace("Đ", "D")
    s = unicodedata.normalize("NFD", s)
    s = "".join(c for c in s if unicodedata.category(c) != "Mn")
    return s.lower().strip()


def parse_amount(s):
    s = str(s or "").lower().strip().replace(" ", "").replace(",", "")
    # Bỏ dấu chấm ngăn nghìn kiểu VN (1.000 / 100.000)
    if s.count(".") == 1 and len(s.split(".")[-1]) == 3 and s.replace(".", "").isdigit():
        s = s.replace(".", "")
    elif s.count(".") > 1:
        s = s.replace(".", "")
    mult = 1
    if s.endswith("k"):
        mult, s = 1_000, s[:-1]
    elif s.endswith("m"):
        mult, s = 1_000_000, s[:-1]
    if not s or not s.replace(".", "").isdigit():
        # cho phép số nguyên thuần
        try:
            value = int(float(s)) * mult
        except Exception:
            raise ValueError("Số tiền không hợp lệ")
    else:
        value = int(float(s)) * mult
    if value < 0:
        raise ValueError("số tiền không được âm")
    return value


def fmt(n):
    return f"{int(round(n)):,}".replace(",", ".")


def signed(n):
    n = int(round(n))
    if n > 0:
        return f"+{fmt(n)}"
    if n < 0:
        return f"-{fmt(-n)}"
    return "0"


def side_label(side):
    return "TÀI" if side == TAI else "XỈU"


# ============================================================
# DỰ ĐOÁN TỪ API NGOÀI (theo bàn) — không nạp phiên để dự đoán
# API: /lc79/tx  và  /lc79/md5  (mảng JSON như ảnh)
# ============================================================
class SessionStore:
    """Chỉ đếm độ chính xác sau khi cược — không phân tích lịch sử."""
    VERSION = "EXTERNAL-API"

    def __init__(self):
        self.recs = {}
        self.perf = deque(maxlen=200)
        self.last_info = {}
        self.validation_ready = True

    def results(self):
        return [v[0] for v in self.recs.values()]

    def ingest(self, records):
        added = 0
        for rec in records or []:
            sid, res = rec.get("session"), rec.get("result")
            if sid is None or res not in (TAI, XIU) or sid in self.recs:
                continue
            self.recs[sid] = (res, rec.get("total", 0), rec.get("dice") or [])
            added += 1
        return added

    def record(self, pred, p_side, actual):
        if pred not in (TAI, XIU) or actual not in (TAI, XIU):
            return
        self.perf.append((pred, actual, max(0.01, min(0.99, float(p_side or 0.5)))))

    def accuracy(self):
        if not self.perf:
            return 0.0
        return sum(1 for pred, actual, _p in self.perf if pred == actual) / len(self.perf) * 100.0


def _normalize_side_label(value):
    value = norm(str(value or "")).upper().replace(" ", "")
    if value in ("TAI", "TÀI", "BIG", "OVER", "HIGH"):
        return TAI
    if value in ("XIU", "XỈU", "SMALL", "UNDER", "LOW"):
        return XIU
    return None


def _parse_confidence(raw):
    if raw is None:
        return 0.5
    s = str(raw).strip().replace("%", "").replace(",", ".")
    try:
        val = float(s)
        if val > 1.0:
            val = val / 100.0
        return max(0.01, min(0.99, val))
    except (TypeError, ValueError):
        return 0.5


def fetch_external_prediction(table=DEFAULT_TABLE, current_sid=None):
    """Gọi API dự đoán theo bàn. Trả dict tín hiệu hoặc None.

    Response mẫu (mảng):
      [{"phien":..., "ket_qua":"Tài", "phien_du_doan":..., "du_doan":"Xỉu",
        "do_tin_cay":"50%", "pattern":"...", "icon":"⏳"}, ...]
    Ưu tiên item icon ⏳ (phiên đang dự đoán), rồi khớp phien_du_doan, rồi phần tử đầu.
    """
    url = predict_url_for(table)
    if not url:
        return None
    try:
        resp = requests.get(url, timeout=PREDICT_TIMEOUT, headers={
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json, text/plain, */*",
        })
        if resp.status_code != 200:
            log.warning("Predict API HTTP %s %s", resp.status_code, url)
            return None
        data = resp.json()
        items = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
        if not items:
            return None

        chosen = None
        # 1) icon đang chờ
        for it in items:
            if not isinstance(it, dict):
                continue
            icon = str(it.get("icon") or "")
            if "⏳" in icon or "hourglass" in icon.lower() or icon.strip() in ("⏳", "⌛"):
                chosen = it
                break
        # 2) khớp phiên
        if chosen is None and current_sid is not None:
            sid_s = str(current_sid)
            for it in items:
                if not isinstance(it, dict):
                    continue
                if str(it.get("phien_du_doan") or it.get("phien") or "") == sid_s:
                    chosen = it
                    break
        # 3) phần tử đầu
        if chosen is None:
            for it in items:
                if isinstance(it, dict):
                    chosen = it
                    break
        if not chosen:
            return None

        side = _normalize_side_label(chosen.get("du_doan") or chosen.get("prediction") or chosen.get("side"))
        if side is None:
            return None

        p_side = _parse_confidence(chosen.get("do_tin_cay") or chosen.get("tin_cay") or chosen.get("confidence"))
        pattern = str(chosen.get("pattern") or "").strip()
        pred_sid = chosen.get("phien_du_doan") or chosen.get("phien") or current_sid
        reason = pattern or f"API · tin_cay={p_side:.0%}"

        return {
            "side": side,
            "p": round(p_side, 4),
            "p_tai": round(p_side if side == TAI else 1.0 - p_side, 4),
            "experts": {"external": p_side},
            "strat": {"model": "EXTERNAL-API", "pred_sid": pred_sid, "pattern": pattern},
            "reason": reason,
            "signal": True,
            "n": 0,
            "ctx": reason,
            "raw": chosen,
        }
    except requests.Timeout:
        log.warning("Predict API timeout %s", url)
        return None
    except Exception as exc:
        log.warning("Predict API lỗi: %s", str(exc)[:140])
        return None


def external_predict_or_skip(st, table, current_sid=None):
    """Lấy du_doan từ API ngoài. Có tín hiệu thì cược; không có thì bỏ qua (không thông báo rác)."""
    url = predict_url_for(table)
    if not url:
        return {
            "side": None, "p": 0.5, "p_tai": 0.5,
            "experts": {}, "strat": {"model": "EXTERNAL-API"},
            "reason": "", "signal": False, "n": 0, "ctx": "no_api",
        }
    info = fetch_external_prediction(table, current_sid)
    if info is None or not info.get("side"):
        return {
            "side": None, "p": 0.5, "p_tai": 0.5,
            "experts": {}, "strat": {"model": "EXTERNAL-API"},
            "reason": "", "signal": False, "n": 0, "ctx": "api_empty",
        }
    return info


# ============================================================
# TRẠNG THÁI
# ============================================================
def normalize_table(value):
    value = norm(str(value or "")).replace("_", "")
    if value in ("md5", "txmd5", "taixiumd5"):
        return "md5"
    if value in ("tx", "thuong", "taixiu", "tx thuong", "taixiu thuong"):
        return "tx"
    return None


DATA_DIR = os.environ.get("LC79_DATA_DIR", "/data").strip() or "/data"


def _log_path(cid, table):
    safe_cid = str(cid).replace("-", "_")
    return os.path.join(DATA_DIR, f"history_{safe_cid}_{table}.json")


def load_persisted_logs(cid, table):
    try:
        with open(_log_path(cid, table), "r", encoding="utf-8") as f:
            rows = json.load(f)
        return rows if isinstance(rows, list) else []
    except (OSError, ValueError, TypeError):
        return []


def persist_logs(cid, table, rows):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        path = _log_path(cid, table)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(list(rows)[-3000:], f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, path)
    except OSError as exc:
        log.warning("Không lưu được lịch sử %s: %s", table, exc)


def format_history_txt(rows, table):
    lines = [
        f"Ban: {TABLES[table]['label']}",
        f"Tong ban ghi: {len(rows)}",
        "PHIEN | DU DOAN | KET QUA | DUNG/SAI | CUOC | LAI/LO | XUC XAC",
        "-" * 90,
    ]
    for r in rows:
        pred = side_label(r.get("pred")) if r.get("pred") else "BO QUA"
        actual = side_label(r.get("res")) if r.get("res") else "?"
        check = "DUNG" if r.get("pred_ok") else ("SAI" if r.get("pred") else "N/A")
        bet = fmt(r.get("bet", 0)) if r.get("placed") else "0"
        delta = signed(r.get("delta")) if r.get("delta") is not None else "CHUA DOI SOAT"
        dice = "-".join(str(x) for x in (r.get("dice") or [])) or "-"
        lines.append(f"{r.get('sid','?')} | {pred} | {actual} | {check} | {bet} | {delta} | {dice}")
    return "\n".join(lines)


def new_state(table="md5"):
    return {
        "table": table, "engine": SessionStore(), "running": False, "gen": 0,
        "auto": False,
        "base_bet": 1000, "mode": "auto", "notify": False,
        "martingale": False, "mg_mult": 1.5, "mg_step": 0,
        "stop_loss": 0, "stop_win": 0, "daily_limit": 0,
        "day": vn_now().strftime("%Y-%m-%d"), "day_bet": 0,
        "session_id": None, "last_open_sid": None, "pending": None, "last_result": None,
        "bet_log": deque(maxlen=3000),
        "balance": 0, "initial_balance": 0, "profit": 0,
        "access_token": "", "jwt": "", "total_win": 0, "total_lose": 0,
        "win_streak": 0, "lose_streak": 0, "total_bet": 0, "nickname": "",
        "login_at": 0, "ws_seen": 0, "ws_connected": False, "poll_last_id": None, "poll_on": False,
    }


def get_state(cid, table=DEFAULT_TABLE):
    table = normalize_table(table) or DEFAULT_TABLE
    with state_lock:
        if cid not in user_states:
            user_states[cid] = {"tables": {"md5": new_state("md5"), "tx": new_state("tx")}, "reserved_bets": 0}
            for table_key in ("md5", "tx"):
                user_states[cid]["tables"][table_key]["bet_log"].extend(load_persisted_logs(cid, table_key)[-3000:])
        root = user_states[cid]
        if "tables" not in root:  # nâng cấp state cũ nếu tiến trình còn giữ dữ liệu
            legacy = root
            root = {"tables": {"md5": legacy, "tx": new_state("tx")}, "reserved_bets": 0}
            legacy["table"] = "md5"
            user_states[cid] = root
        return root["tables"][table]


def current_bet(st):
    """Vốn gốc + tự tăng khi thắng 2 phiên liên tiếp (x1.5 → x2). Không gấp thếp."""
    base = int(st.get("base_bet") or 0)
    if base <= 0:
        return 0
    wins = int(st.get("win_streak") or 0)
    if wins >= 3:
        # Thắng ≥3 tay liên tiếp: x2 vốn gốc
        return int(round(base * 2.0))
    if wins >= 2:
        # Thắng 2 tay: x1.5 vốn gốc
        return int(round(base * 1.5))
    return base


def risk_block(st, amount):
    today = vn_now().strftime("%Y-%m-%d")
    if st["day"] != today:
        st["day"], st["day_bet"] = today, 0
    # Sai ≥3 tay liên tiếp trên bàn này → tự dừng bàn
    if int(st.get("lose_streak") or 0) >= 3:
        return "Sai 3 tay liên tiếp · tự dừng bàn"
    if st["stop_loss"] and st["profit"] <= -st["stop_loss"]:
        return "Đã chạm mức dừng lỗ"
    if st["stop_win"] and st["profit"] >= st["stop_win"]:
        return "Đã chạm mức dừng lãi"
    if st["daily_limit"] and st["day_bet"] + amount > st["daily_limit"]:
        return "Vượt giới hạn cược ngày"
    if amount > int(st.get("balance") or 0):
        return "Số dư thật không đủ hoặc chưa đọc được"
    return None


def _apply_auto_settings(st, params):
    """Áp dụng stop-loss / stop-win / daily limit từ web."""
    params = params or {}
    for src, dst in (("sl", "stop_loss"), ("sw", "stop_win"), ("limit", "daily_limit")):
        if src in params and str(params[src]).strip() != "":
            st[dst] = parse_amount(str(params[src]))


def start_table_runtime(cid, table):
    """Kết nối bàn khi bật Auto — dự đoán lấy từ API ngoài, không nạp phiên nội bộ."""
    table = normalize_table(table) or DEFAULT_TABLE
    st = get_state(cid, table)
    if st.get("running"):
        return True, "Bàn đã chạy"
    token = str(st.get("jwt") or "").strip()
    if not token:
        return False, "Chưa có phiên đăng nhập LC79"
    if not predict_url_for(table):
        return False, "Chưa cấu hình API dự đoán"
    with state_lock:
        st["login_at"] = time.time()
        st["running"] = True
        st["ws_connected"] = False
        st["gen"] += 1
        generation = st["gen"]
    threading.Thread(target=start_websocket, args=(cid, token, table), daemon=True).start()
    threading.Thread(target=sync_loop, args=(cid, table, generation), daemon=True).start()
    return True, f"Đã bật {TABLES[table]['label']}"


def _set_auto(cid, table, enabled, amount=None, params=None):
    """Bật/tắt auto cho một bàn (web)."""
    st = get_state(cid, table)
    if enabled:
        if not st.get("access_token") or not st.get("jwt"):
            return False, "Chưa đăng nhập LC79"
        # Kiểm tra và áp dụng cấu hình trước khi mở bất kỳ luồng tải phiên nào.
        # Như vậy cấu hình sai không để lại websocket/sync loop chạy nền ngoài ý muốn.
        try:
            _apply_auto_settings(st, params or {})
            if amount is not None and str(amount).strip() != "":
                value = parse_amount(str(amount))
                if value <= 0:
                    raise ValueError("Mức cược phải lớn hơn 0")
                st["base_bet"] = value
        except ValueError as exc:
            return False, str(exc)
        if int(st.get("base_bet") or 0) <= 0:
            return False, "Mức cược phải lớn hơn 0"

        newly_started = False
        if not st.get("running"):
            started, start_message = start_table_runtime(cid, table)
            if not started:
                return False, start_message
            newly_started = True
        balance = refresh_state_balance(st)
        if balance is None:
            if newly_started:
                stop_user(cid, table)
            return False, "Không xác minh được số dư thật từ API"
        block = risk_block(st, current_bet(st))
        if block:
            if newly_started:
                stop_user(cid, table)
            return False, block
        st["auto"] = True
        return True, f"Đã bật {TABLES[table]['label']} · {fmt(st['base_bet'])}"
    st["auto"] = False
    return True, f"Đã tắt {TABLES[table]['label']}"


def apply_shared_balance(st, balance):
    """Cập nhật số dư API thật cho cả hai bàn dùng cùng tài khoản."""
    if balance is None:
        return
    access, jwt = st.get("access_token"), st.get("jwt")
    for root in list(user_states.values()):
        if "tables" not in root:
            continue
        for other in root["tables"].values():
            if other.get("access_token") == access and other.get("jwt") == jwt:
                other["balance"] = int(balance)
                other["profit"] = int(balance) - int(other.get("initial_balance") or 0)


def refresh_state_balance(st):
    """Đồng bộ số dư thật; cùng tài khoản nên cập nhật hiển thị cho cả hai bàn."""
    balance = fetch_account_balance(st.get("access_token"), st.get("jwt"))
    if balance is not None:
        apply_shared_balance(st, balance)
    return balance


# ============================================================
# NẠP PHIÊN + ĐĂNG NHẬP
# ============================================================
def _payload_items(data):
    """Lấy danh sách phiên từ nhiều kiểu JSON LC79 từng trả về."""
    if isinstance(data, list):
        return data, {}
    if not isinstance(data, dict):
        return [], {}
    for key in ("list", "sessions", "items", "records"):
        if isinstance(data.get(key), list):
            return data[key], data
    nested = data.get("data")
    if isinstance(nested, list):
        return nested, data
    if isinstance(nested, dict):
        for key in ("list", "sessions", "items", "records"):
            if isinstance(nested.get(key), list):
                return nested[key], nested
    return [], data


def _normalize_result(value):
    value = norm(str(value or "")).upper().replace(" ", "")
    if value in ("TAI", "BIG", "OVER", "HIGH"):
        return TAI
    if value in ("XIU", "SMALL", "UNDER", "LOW"):
        return XIU
    return None


def parse_lines(data):
    """Chuẩn hóa lịch sử cả API txmd5 và API tx cũ từ lc79.py."""
    items, _meta = _payload_items(data)
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        sid = it.get("id", it.get("session", it.get("Phien", it.get("sessionId"))))
        if sid is None:
            continue
        result = _normalize_result(
            it.get("resultTruyenThong", it.get("Ket_qua", it.get("result", it.get("outcome"))))
        )
        if result not in (TAI, XIU):
            continue
        dice = it.get("dices")
        if not isinstance(dice, (list, tuple)) or len(dice) != 3:
            dice = [it.get("Xuc_xac_1"), it.get("Xuc_xac_2"), it.get("Xuc_xac_3")]
        try:
            dice = [int(x) for x in dice]
            if len(dice) != 3 or any(x < 1 or x > 6 for x in dice):
                dice = []
        except (TypeError, ValueError):
            dice = []
        raw_total = it.get("point", it.get("Tong", it.get("total")))
        try:
            total = int(raw_total) if raw_total is not None else (sum(dice) if dice else None)
        except (TypeError, ValueError):
            total = sum(dice) if dice else None
        out.append({"session": normalize_sid(sid), "dice": dice, "total": total, "result": result})
    # Gộp trùng ID và sắp xếp từ cũ đến mới, không phụ thuộc API trả tăng hay giảm.
    unique = {}
    for item in out:
        unique[item["session"]] = item
    return sorted(unique.values(), key=lambda x: sid_sort_key(x["session"]))


def _fetch_paginated(url, origin):
    headers = {"User-Agent": "Mozilla/5.0", "Origin": origin}
    response = requests.get(url, headers=headers, timeout=12)
    if response.status_code != 200:
        return []
    payload = response.json()
    items, meta = _payload_items(payload)
    collected = list(items)
    # Chỉ phân trang khi API có metadata xác nhận; không đoán tham số khi API không hỗ trợ.
    pagination = meta.get("pagination", meta.get("meta", {})) if isinstance(meta, dict) else {}
    if isinstance(pagination, dict):
        current = pagination.get("current_page", pagination.get("currentPage", pagination.get("page", 1)))
        last = pagination.get("last_page", pagination.get("total_pages", pagination.get("totalPages", current)))
        try:
            current, last = int(current), min(int(last), 100)
        except (TypeError, ValueError):
            current, last = 1, 1
        for page in range(current + 1, last + 1):
            page_response = requests.get(url, params={"page": page}, headers=headers, timeout=12)
            if page_response.status_code != 200:
                break
            page_items, _ = _payload_items(page_response.json())
            if not page_items:
                break
            collected.extend(page_items)
    return parse_lines(collected)


def fetch_history_from_api(table=DEFAULT_TABLE, limit=None):
    """Nạp lịch sử từ API riêng của bàn được chọn."""
    table = normalize_table(table) or DEFAULT_TABLE
    cfg = TABLES[table]
    urls = [u for u in (cfg["history"], cfg["fallback"]) if u]
    for url in urls:
        try:
            arr = _fetch_paginated(url, cfg["origin"])
            if arr:
                return arr if limit is None else arr[-limit:]
        except Exception as exc:
            log.warning("Lỗi lấy lịch sử %s: %s", url, short(exc, 100) if 'short' in globals() else str(exc)[:100])
    return []


def fetch_latest_results(table=DEFAULT_TABLE, expect=None, retries=4):
    arr = []
    for _ in range(retries):
        arr = fetch_history_from_api(table, MAX_HISTORY)
        if arr and (expect is None or arr[-1]["result"] == expect):
            return arr
        time.sleep(1.0)
    return arr


def md5_hash(t):
    return hashlib.md5(t.encode("utf-8")).hexdigest()


def _lc79_body_error(data):
    """Lấy thông điệp lỗi từ nhiều lớp response của LC79 mà không log credential."""
    if not isinstance(data, (dict, list)):
        return ""
    # Các API cũ đôi khi bọc response trong data/result.
    stack = [data]
    while stack:
        item = stack.pop(0)
        if isinstance(item, dict):
            success = item.get("success")
            code = item.get("code")
            if success is False:
                return str(item.get("message") or item.get("msg") or item.get("error") or "LC79 từ chối yêu cầu")[:180]
            if code not in (None, 0, "0", "200", 200, True):
                msg = item.get("message") or item.get("msg") or item.get("error")
                if msg:
                    return str(msg)[:180]
            for k in ("data", "result", "error", "errors", "response"):
                v = item.get(k)
                if isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(item, list):
            stack.extend(x for x in item if isinstance(x, (dict, list)))
    return ""


def _lc79_account_probe(jwt, timeout=15):
    """Ping JWT qua detail-info theo đúng tài liệu Tele68/LC79."""
    token = str(jwt or "")
    headers = dict(LC79_HEADERS)
    headers["Authorization"] = f"Bearer {token}"
    response = requests.get(
        ACCOUNT_URL,
        params={"cp": "R", "cl": "R", "pf": "web", "at": token},
        headers=headers,
        timeout=timeout,
    )
    try:
        body = response.json()
    except ValueError:
        body = {"message": (response.text or "")[:200]}
    if _api_payload_auth_expired(response.status_code, body):
        raise RuntimeError(
            "LC79 từ chối Token. Vui lòng không mở App trên điện thoại khi dùng Web."
        )
    if response.status_code >= 400:
        raise RuntimeError(f"API detail-info LC79 trả HTTP {response.status_code}")
    body_error = _lc79_body_error(body)
    if body_error:
        raise RuntimeError(str(body_error)[:180])
    # HTTP 2xx + payload không có mã lỗi xác thực được xem là ping thành công.
    balance = _parse_int_money(_find_nested_value(body, ("balance", "money", "availableBalance")), None)
    return balance, body


def fetch_account_balance(access_token, jwt):
    """Đọc số dư bằng JWT theo đúng API tài liệu; không thử thay JWT bằng accessToken."""
    if not jwt:
        return None
    try:
        balance, _body = _lc79_account_probe(jwt, timeout=12)
        return balance
    except Exception as exc:
        log.warning("API số dư LC79 không xác minh được JWT: %s", str(exc)[:140])
        return None


def _lc79_success_flag(data):
    """Nhận success/code cả khi nhà cung cấp bọc response trong data/result."""
    if not isinstance(data, dict):
        return False
    success = _find_nested_value(data, ("success",))
    code = _find_nested_value(data, ("code",))
    if success is False or (isinstance(success, str) and success.lower() in ("false", "fail", "failed")):
        return False
    if success is True or success == 1 or (isinstance(success, str) and success.lower() in ("1", "true", "success", "ok")):
        return True
    return code in (0, "0", 200, "200")


def _lc79_decode_nickname(session_key, response_data, username):
    """Giải mã nickname trong sessionKey; chỉ dùng nickname response làm fallback."""
    nickname = ""
    if session_key:
        raw_key = str(session_key).strip()
        # sessionKey từ API là Base64 JSON; hỗ trợ cả Base64URL và Base64 chuẩn.
        candidates = [raw_key, raw_key.replace("-", "+").replace("_", "/")]
        for candidate in candidates:
            try:
                padded = candidate + "=" * (-len(candidate) % 4)
                decoded = base64.b64decode(padded.encode("ascii"), validate=False)
                parsed = json.loads(decoded.decode("utf-8-sig"))
                nickname = str(_find_nested_value(parsed, ("nickname", "nickName", "nick_name")) or "").strip()
                if nickname:
                    break
            except Exception:
                continue
    nickname = nickname or str(_find_nested_value(response_data, ("nickName", "nickname", "nick_name")) or username).strip()
    return nickname or str(username)


def login_and_get_token(u, p):
    """Đăng nhập theo đúng luồng 2 bước trong hd.txt / naprutlc79.py.

    Quan trọng: việc cấp JWT ở lobby là kết quả đăng nhập. Hai API account/profile
    chỉ dùng đọc dữ liệu sau đăng nhập, không được dùng làm cổng từ chối login.
    """
    try:
        # Bước 1: lấy accessToken + sessionKey
        first = requests.get(
            "https://apifo88daigia.tele68.com/api",
            params={"c": "3", "un": u, "pw": md5_hash(p), "cp": "R", "cl": "R", "pf": "web", "at": ""},
            headers=dict(LC79_HEADERS),
            timeout=18,
        )
        try:
            login_response = first.json()
        except ValueError:
            return {"_error": f"API đăng nhập LC79 trả dữ liệu không hợp lệ (HTTP {first.status_code})"}
        if first.status_code >= 400 or not isinstance(login_response, dict) or login_response.get("success") is not True:
            detail = _lc79_body_error(login_response) or "LC79 từ chối tài khoản hoặc mật khẩu"
            return {"_error": str(detail)[:180]}

        access = str(login_response.get("accessToken") or "").strip()
        session_key = str(login_response.get("sessionKey") or "").strip()
        if not access or not session_key:
            return {"_error": "API LC79 thiếu accessToken hoặc sessionKey ở bước 1"}

        # Giải mã cả Base64 chuẩn lẫn Base64URL, có xử lý padding thiếu.
        nickname = _lc79_decode_nickname(session_key, login_response, u)
        if not nickname or nickname == str(u):
            # Có API chỉ trả nickname trực tiếp trong response; không tự suy đoán từ username.
            has_nickname = bool(_find_nested_value(login_response, ("nickname", "nickName", "nick_name")))
            if not has_nickname:
                return {"_error": "sessionKey LC79 không chứa nickname hợp lệ"}

        # Bước 2: lobby cấp JWT. Dùng JWT này làm kết quả xác thực chính.
        lobby_url = "https://wlb.tele68.com/v1/lobby/auth/login"
        lobby_resp = requests.post(
            lobby_url,
            params={"cp": "R", "cl": "R", "pf": "web", "at": ""},
            headers=dict(LC79_HEADERS),
            json={"nickName": nickname, "accessToken": access},
            timeout=18,
        )
        try:
            lobby_raw = lobby_resp.json()
        except ValueError:
            lobby_raw = {"message": (lobby_resp.text or "")[:200]}
        if lobby_resp.status_code >= 400:
            detail = _lc79_body_error(lobby_raw) or f"API lobby LC79 trả HTTP {lobby_resp.status_code}"
            return {"_error": str(detail)[:180]}
        jwt = _extract_lobby_jwt(lobby_raw)
        if not jwt:
            detail = _lc79_body_error(lobby_raw) or "LC79 không cấp JWT ở bước xác thực lobby"
            return {"_error": str(detail)[:180]}

        # Chỉ đọc số dư theo kiểu best-effort. Không dùng API account/profile
        # để phủ định một JWT mà chính endpoint lobby vừa cấp.
        money = None
        try:
            money = fetch_account_balance(access, jwt)
        except Exception as exc:
            log.warning("LC79 balance lookup after successful lobby login failed: %s", str(exc)[:120])
        if money is None:
            remote = lobby_raw.get("remoteLoginResp", {}) if isinstance(lobby_raw, dict) else {}
            if isinstance(remote, dict):
                money = _parse_int_money(remote.get("money", remote.get("balance")), 0)
            else:
                money = 0

        return {"token": jwt, "access": access, "nickname": nickname, "money": int(money or 0)}
    except requests.RequestException as exc:
        log.warning("LC79 login network error: %s", str(exc)[:140])
        return {"_error": "Không kết nối được máy chủ xác thực LC79. Vui lòng thử lại."}
    except Exception as exc:
        log.warning("LC79 login flow error: %s", str(exc)[:160])
        return {"_error": "Đăng nhập LC79 chưa thành công. Vui lòng thử lại."}


# ============================================================
# CHỐT PHIÊN, CƯỢC, WEBSOCKET
# ============================================================
def explain_round_reason(info, st):
    """Lý do ngắn gọn từ API dự đoán."""
    raw = str((info or {}).get("reason") or "").strip()
    return raw


def open_round(cid, sid, table=DEFAULT_TABLE):
    """Mở một ván trong đúng bàn, không dùng nhầm lịch sử bàn còn lại."""
    table = normalize_table(table) or DEFAULT_TABLE
    st = get_state(cid, table)
    with state_lock:
        if sid is None:
            return None
        if st.get("last_open_sid") is not None and str(st["last_open_sid"]) == str(sid):
            return st.get("pending")
        st["session_id"] = sid
        st["last_open_sid"] = sid
        # Chỉ dự đoán khi Auto đã bật (web)
        if not st.get("auto"):
            st["pending"] = None
            return None
        # Dự đoán từ API ngoài — không còn thuật toán nội bộ
        info = external_predict_or_skip(st, table, sid)
        st["engine"].last_info = info
        p_side = float(info.get("p") or 0.5)
        reason = explain_round_reason(info, st)
        pend = {
            "sid": sid, "table": table, "pred": info["side"], "p_side": p_side, "p_tai": info["p_tai"],
            "experts": info["experts"], "strat": info.get("strat", {}), "placed": False, "sent": False, "bet": 0,
            "status": [], "done": False,
            "balance_before": int(st.get("balance") or 0), "balance_after_bet": None,
            "reason": reason,
        }
        st["pending"] = pend
        pre = {
            "sid": sid, "pred": info.get("side"), "res": None, "dice": None, "total": None,
            "pred_ok": None, "placed": False, "bet": 0, "won": None, "delta": None,
            "reason": reason, "time": vn_now().strftime("%H:%M:%S %d/%m/%Y"), "status": "pending",
        }
        logs = st["bet_log"]
        updated = False
        for i in range(len(logs) - 1, -1, -1):
            if str(logs[i].get("sid")) == str(sid):
                logs[i] = pre
                updated = True
                break
        if not updated:
            logs.append(pre)
    return pend


def poll_round(cid, arr, table=DEFAULT_TABLE):
    """Dự phòng khi websocket không gửi sự kiện phiên mới cho bàn này."""
    st = get_state(cid, table)
    now = time.time()
    if st.get("ws_seen", 0) and now - st["ws_seen"] < 90:
        return
    if now - st.get("login_at", now) < 60:
        return
    last = arr[-1]
    sid_last = last["session"]
    if not st.get("poll_on"):
        st["poll_on"] = True
        push_event(cid, "Websocket", "Chưa có phiên mới · theo dõi qua lịch sử", "warn")
    to_settle = None
    with state_lock:
        if st.get("poll_last_id") == sid_last:
            return
        st["poll_last_id"] = sid_last
        if st["pending"] is not None:
            to_settle = st["pending"]
            st["pending"] = None
            to_settle["done"] = True
    if to_settle is not None:
        settle_round(cid, last["result"], last["dice"], to_settle, table)
    try:
        next_sid = int(sid_last) + 1
    except (TypeError, ValueError):
        next_sid = None
    if next_sid is not None:
        open_round(cid, next_sid, table)


def pend_status(cid, pend, line):
    if pend is None:
        return
    with state_lock:
        if pend.get("done"):
            return
        pend["status"] = (pend["status"] + [str(line)])[-4:]
    push_event(cid, "Cược", str(line)[:120], "info")


def short(x, n=28):
    s = str(x).replace("\n", " ")
    return s if len(s) <= n else s[:n - 1] + "…"


def settle_round(cid, res, ws_dices, pend, table=DEFAULT_TABLE):
    table = normalize_table(table) or (pend.get("table") if pend else DEFAULT_TABLE)
    st = get_state(cid, table)
    sid = pend["sid"] if pend else st.get("session_id")
    dice = ws_dices or []

    # Nạp kết quả phiên vào store (chỉ lưu lịch sử, không học mô hình).
    with state_lock:
        if pend is not None:
            if sid is not None:
                st["engine"].ingest([{"session": normalize_sid(sid), "result": res,
                                      "total": sum(dice) if dice else None, "dice": dice}])
            if pend.get("pred") is not None:
                st["engine"].record(pend["pred"], pend.get("p_side", 0.5), res)
            pend["done"] = True
        pred = pend.get("pred") if pend else None
        pred_ok = None if pred is None else (pred == res)
        placed = bool(pend and pend.get("placed"))
        bet = int(pend.get("bet", 0)) if pend else 0
        balance_before = pend.get("balance_before") if pend else None
        won = (pred == res) if placed else None
        if placed:
            if won:
                st["total_win"] += 1
                st["win_streak"] += 1
                st["lose_streak"] = 0
            else:
                st["total_lose"] += 1
                st["lose_streak"] += 1
                st["win_streak"] = 0
                # Sai 3 tay liên tiếp trên bàn này → tự tắt Auto bàn
                if st["lose_streak"] >= 3:
                    st["auto"] = False

    # API lịch sử bổ sung xúc xắc/phiên; API tài khoản xác nhận lãi lỗ thật, không mô phỏng.
    history = fetch_latest_results(table, expect=res, retries=2)
    matched = None
    for item in history:
        if str(item["session"]) == str(sid):
            matched = item
            break
    if matched is None and sid is None and history and history[-1]["result"] == res:
        matched = history[-1]
    if matched:
        dice = matched.get("dice") or dice
        if sid is not None and dice:
            with state_lock:
                key = normalize_sid(sid)
                if key in st["engine"].recs:
                    st["engine"].recs[key] = (res, matched.get("total"), dice)

    real_balance = None
    if placed:
        for attempt in range(3):
            real_balance = fetch_account_balance(st.get("access_token"), st.get("jwt"))
            if real_balance is not None:
                break
            if attempt < 2:
                time.sleep(1.0)

    with state_lock:
        delta = None
        if real_balance is not None:
            apply_shared_balance(st, real_balance)
            if balance_before is not None:
                delta = real_balance - int(balance_before)
        elif placed:
            # Không có số dư đối soát: khóa Auto cả hai bàn thay vì tiếp tục bằng số dư cũ.
            for root in list(user_states.values()):
                if "tables" in root:
                    for other in root["tables"].values():
                        if other.get("access_token") == st.get("access_token") and other.get("jwt") == st.get("jwt"):
                            other["auto"] = False
            push_event(cid, "Số dư", "Không đối soát được sau cược · Auto đã tắt", "warn")
        release_bet_reservation(cid, pend)
        reason = ""
        try:
            if pend:
                reason = str(pend.get("reason") or "")
            if not reason and st.get("engine"):
                info = getattr(st["engine"], "last_info", None) or {}
                reason = str(info.get("reason") or "")
        except Exception:
            reason = ""
        rec = {
            "sid": sid if sid is not None else "?",
            "pred": pred, "res": res, "dice": dice,
            "total": sum(dice) if dice else (matched.get("total") if matched else None),
            "pred_ok": pred_ok, "placed": placed, "bet": bet, "won": won, "delta": delta,
            "reason": reason, "time": vn_now().strftime("%H:%M:%S %d/%m/%Y"), "status": "done",
        }
        logs = st["bet_log"]
        updated = False
        for i in range(len(logs) - 1, -1, -1):
            if str(logs[i].get("sid")) == str(rec["sid"]):
                logs[i] = rec
                updated = True
                break
        if not updated:
            logs.append(rec)
        st["last_result"] = rec
        persist_logs(cid, table, st["bet_log"])
        if placed:
            movement = signed(delta) if delta is not None else "chưa đối soát số dư"
            push_event(cid, f"{'Thắng' if pred_ok else 'Thua'} {TABLES[table]['label']}", movement,
                       "ok" if pred_ok else "warn")



def handle_ack(cid, data, pend, table=DEFAULT_TABLE):
    st = get_state(cid, table)
    if pend is None or pend.get("done"):
        return
    rejected = isinstance(data, dict) and (
        bool(data.get("error")) or data.get("success") is False
        or data.get("status") in (False, 0, "error", "fail", "failed"))
    if rejected:
        release_bet_reservation(cid, pend)
        line = f"Server từ chối: {short(data)}"
    elif data is None:
        line = "Chờ server xác nhận..."
    else:
        line = "Server đã nhận cược"
        with state_lock:
            if not pend["placed"]:
                pend["placed"] = True
                pend.setdefault("balance_before", int(st.get("balance") or 0))
                st["day_bet"] += pend["bet"]
                st["total_bet"] += pend["bet"]
    pend_status(cid, pend, line)


def start_websocket(cid, token, table=DEFAULT_TABLE):
    table = normalize_table(table) or DEFAULT_TABLE
    cfg = TABLES[table]
    st = get_state(cid, table)
    socket_key = (cid, table)
    old = active_sockets.pop(socket_key, None)
    if old is not None:
        try:
            old.disconnect()
        except Exception:
            pass

    sio = socketio.Client(reconnection=True, reconnection_attempts=99999, reconnection_delay=3,
                          logger=False, engineio_logger=False)
    active_sockets[socket_key] = sio

    @sio.event(namespace=cfg["namespace"])
    def connect():
        st["ws_connected"] = True

    @sio.on("new-session", namespace=cfg["namespace"])
    def new_sess(d):
        st["ws_seen"] = time.time()
        open_round(cid, d.get("id"), table)

    @sio.on("tick-update", namespace=cfg["namespace"])
    def tk(d):
        if str(d.get("state", "")).upper() != "BETTING":
            return
        block, amount, pred, pend = None, 0, None, None
        with state_lock:
            pend = st["pending"]
            if not st["auto"] or pend is None or pend["pred"] is None or pend["sent"]:
                return
            amount = current_bet(st)
            block = risk_block(st, amount)
            root = user_states.get(cid, {})
            reserved = int(root.get("reserved_bets", 0)) if "tables" in root else 0
            available = int(st.get("balance") or 0) - reserved
            if block is None and amount > available:
                block = "Số dư khả dụng đã được bàn còn lại giữ chỗ"
            if block:
                st["auto"] = False
            else:
                pend["sent"] = True
                pend["bet"] = amount
                pend["reservation"] = True
                root["reserved_bets"] = reserved + amount
                pend["balance_before"] = int(st.get("balance") or 0)
                pred = pend["pred"]
        if block:
            pend_status(cid, pend, f"Tự tắt: {short(block, 24)}")
            return
        pend_status(cid, pend, f"Gửi {side_label(pred)} {fmt(amount)}")
        push_event(cid, f"Cược {TABLES[table]['label']}", f"{side_label(pred)} · {fmt(amount)}", "bet")
        with state_lock:
            for i in range(len(st["bet_log"]) - 1, -1, -1):
                if str(st["bet_log"][i].get("sid")) == str(pend.get("sid")):
                    st["bet_log"][i]["placed"] = True
                    st["bet_log"][i]["bet"] = amount
                    st["bet_log"][i]["status"] = "betting"
                    break
        sio.emit("bet", {"type": pred, "amount": amount}, namespace=cfg["namespace"],
                 callback=lambda *args, _p=pend: handle_ack(cid, args[0] if args else None, _p, table))

    @sio.on("bet-result", namespace=cfg["namespace"])
    def br(d):
        confirmed = False
        with state_lock:
            pend = st["pending"]
            if "postBalance" in d:
                try:
                    apply_shared_balance(st, int(float(d["postBalance"])))
                    if pend is not None:
                        pend["balance_after_bet"] = st["balance"]
                        release_bet_reservation(cid, pend)
                except (TypeError, ValueError):
                    pass
                if pend and pend["sent"] and not pend["placed"]:
                    pend["placed"] = True
                    st["day_bet"] += pend["bet"]
                    st["total_bet"] += pend["bet"]
                    confirmed = True
        if confirmed:
            pend_status(cid, pend, f"Cược thành công, số dư {fmt(d['postBalance'])}")
        elif pend is not None:
            pend_status(cid, pend, f"Server: {short(d)}")
        else:
            push_event(cid, "Server", short(d, 120), "info")

    @sio.on("session-result", namespace=cfg["namespace"])
    def sr(d):
        res = d.get("resultTruyenThong")
        if res not in (TAI, XIU):
            return
        # Lấy đúng thẻ của ván vừa kết thúc tại thời điểm nhận kết quả, để ván mới không bị ghi đè.
        with state_lock:
            pend = st["pending"]
            st["pending"] = None
        threading.Thread(target=settle_round, args=(cid, res, d.get("dices"), pend, table), daemon=True).start()

    @sio.event(namespace=cfg["namespace"])
    def disconnect():
        st["ws_connected"] = False

    @sio.on("connect_error")
    def connect_error(data):
        st["ws_connected"] = False
        push_event(cid, "WebSocket", f"Không kết nối: {str(data)[:80]}", "warn")

    try:
        sio.connect(cfg["ws_url"], socketio_path=cfg["ws_path"], namespaces=[cfg["namespace"]],
                    transports=["websocket"], auth={"token": token},
                    headers={"User-Agent": "Mozilla/5.0", "Origin": cfg["origin"]})
        sio.wait()
    except Exception as e:
        st["ws_connected"] = False
        push_event(cid, "WebSocket", f"Mất kết nối: {str(e)[:80]}", "warn")


def release_bet_reservation(cid, pend):
    """Giải phóng phần số dư đang được một bàn giữ chỗ để tránh hai bàn cược vượt số dư."""
    if not pend or not pend.get("reservation"):
        return
    with state_lock:
        root = user_states.get(cid)
        if root and "tables" in root:
            root["reserved_bets"] = max(0, int(root.get("reserved_bets", 0)) - int(pend.get("bet", 0)))
        pend["reservation"] = False


def stop_user(cid, table=None):
    targets = [normalize_table(table)] if table else ["md5", "tx"]
    for key in targets:
        if not key:
            continue
        st = get_state(cid, key)
        release_bet_reservation(cid, st.get("pending"))
        st["pending"] = None
        st["running"] = False
        st["ws_connected"] = False
        st["gen"] += 1
        st["auto"] = False
        # Mỗi lần dừng: xoá hết log cược
        st["bet_log"].clear()
        st["total_win"] = 0
        st["total_lose"] = 0
        st["total_bet"] = 0
        st["win_streak"] = 0
        st["lose_streak"] = 0
        st["mg_step"] = 0
        st["profit"] = 0
        try:
            persist_logs(cid, key, [])
        except Exception:
            pass
        sio = active_sockets.pop((cid, key), None)
        if sio is not None:
            try:
                sio.disconnect()
            except Exception:
                pass


def sync_loop(cid, table, generation):
    """Đồng bộ lịch sử định kỳ cho bàn tương ứng, đồng thời dự phòng khi WS im lặng."""
    st = get_state(cid, table)
    while st.get("running") and st.get("gen") == generation:
        try:
            records = fetch_history_from_api(table, MAX_HISTORY)
            if records:
                with state_lock:
                    st["engine"].ingest(records)
                poll_round(cid, records, table)
        except Exception as exc:
            log.warning("Sync %s của chat %s lỗi: %s", table, cid, short(exc, 120))
        time.sleep(SYNC_INTERVAL)



def main():
    log.info("LC79 Web · PORT=%s", os.environ.get("PORT", "10000"))
    run_web()


if __name__ == "__main__":
    main()
