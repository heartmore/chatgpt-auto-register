#!/usr/bin/env python3
"""ChatGPT Auto Register - Web GUI (Open Source Edition)"""

import copy, json, os, queue, sys, threading, time
from pathlib import Path

sys.stdout.reconfigure(line_buffering=True)

from flask import Flask, request, jsonify, Response, send_file

app = Flask(__name__)
sys.path.insert(0, str(Path(__file__).parent))
from smsbower import SmsBower
import auto_register as ar

# ── Paths ──
ROOT = Path(__file__).parent
COOKIES_FILE = ROOT / "icloud_cookies.json"
BLACKLIST_FILE = ROOT / "email_blacklist.json"
CONFIG_FILE = ROOT / "config.json"
RESULTS_DIR = ROOT / "results"

# ── Locks ──
icloud_lock = threading.Lock()
_blacklist_lock = threading.Lock()
_claimed_lock = threading.Lock()
_result_lock = threading.Lock()
_log_lock = threading.Lock()

_email_blacklist = set()
_claimed_emails = set()


def _load_email_blacklist():
    global _email_blacklist
    if BLACKLIST_FILE.exists():
        try:
            _email_blacklist = set(json.loads(BLACKLIST_FILE.read_text(encoding="utf-8")))
        except Exception:
            pass


def _save_email_blacklist():
    with _blacklist_lock:
        try:
            BLACKLIST_FILE.write_text(json.dumps(
                sorted(_email_blacklist), indent=2, ensure_ascii=False
            ) + "\n", encoding="utf-8")
        except Exception:
            pass


_load_email_blacklist()


def _load_config():
    """从 config.json 加载配置到 _state"""
    if CONFIG_FILE.exists():
        try:
            saved = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            cfg = _state["config"]
            # 合并所有顶层简单字段
            for k in ("proxy", "country", "service", "max_price", "sms_timeout",
                      "code_timeout", "bind_email"):
                if k in saved:
                    cfg[k] = saved[k]
            # 合并嵌套对象
            for section in ("smsbower", "register", "icloud", "sub2api"):
                if section in saved and isinstance(saved[section], dict):
                    cfg.setdefault(section, {})
                    cfg[section].update(saved[section])
        except Exception:
            pass


_state = {
    "results": [],
    "worker": None,               # {"thread": Thread, "stop": threading.Event}
    "config": {
        "smsbower": {"api_key": ""},
        "register": {"password": ""},
        "proxy": "",
        "country": "151",
        "service": "dr",
        "max_price": "",
        "sms_timeout": 30,
        "code_timeout": 30,
        "icloud": {"user": "", "pass": ""},
        "sub2api": {"url": "", "email": "", "pwd": "", "group": "CHATGPT", "proxy_id": 0},
        "bind_email": "",
    },
    "log_queue": queue.Queue(),
    "log_lines": [],
    "log_cursor": 0,
}

_load_config()


def _log(msg, tag="info", wid=1):
    prefix = f"[W{wid}] " if wid else ""
    ts = time.strftime("%H:%M:%S")
    item = {"msg": prefix + str(msg), "tag": tag, "time": ts, "wid": wid}
    _state["log_queue"].put(item)
    with _log_lock:
        _state["log_lines"].append(item)
        if len(_state["log_lines"]) > 2000:
            _state["log_lines"] = _state["log_lines"][-1500:]


# ============================================================
# API Routes
# ============================================================

@app.route("/")
def index():
    return Response(_HTML, mimetype="text/html; charset=utf-8")


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    if request.method == "POST":
        d = request.json or {}
        cfg = _state["config"]
        for k in ["api_key", "proxy", "country", "max_price", "sms_timeout",
                   "imap_user", "imap_pass", "sub2api_url", "sub2api_email",
                   "sub2api_pwd", "sub2api_group", "sub2api_proxy_id", "bind_email"]:
            if k in d and d[k] is not None:
                if k == "api_key": cfg["smsbower"]["api_key"] = d[k]
                elif k == "password": cfg["register"]["password"] = d[k]
                elif k in ("sms_timeout",): cfg[k] = int(d[k]) if d[k] else 30
                elif k in ("proxy", "country", "max_price"): cfg[k] = d[k]
                elif k == "imap_user": cfg["icloud"] = cfg.get("icloud", {}); cfg["icloud"]["user"] = d[k]
                elif k == "imap_pass": cfg["icloud"] = cfg.get("icloud", {}); cfg["icloud"]["pass"] = d[k]
                elif k == "sub2api_url": cfg["sub2api"] = cfg.get("sub2api", {}); cfg["sub2api"]["url"] = d[k]
                elif k == "sub2api_email": cfg["sub2api"] = cfg.get("sub2api", {}); cfg["sub2api"]["email"] = d[k]
                elif k == "sub2api_pwd": cfg["sub2api"] = cfg.get("sub2api", {}); cfg["sub2api"]["pwd"] = d[k]
                elif k == "sub2api_group": cfg["sub2api"] = cfg.get("sub2api", {}); cfg["sub2api"]["group"] = d[k]
                elif k == "sub2api_proxy_id": cfg["sub2api"] = cfg.get("sub2api", {}); cfg["sub2api"]["proxy_id"] = int(d[k]) if d[k] else 0
                elif k == "bind_email": cfg["bind_email"] = d[k]
        _save_config_file(cfg)
        return jsonify({"ok": True, "config": _sanitize_config(cfg)})
    return jsonify({"ok": True, "config": _sanitize_config(_state["config"])})


@app.route("/api/balance")
def api_balance():
    key = _state.get("config", {}).get("smsbower", {}).get("api_key", "")
    if not key: return jsonify({"ok": False, "error": "No API key"})
    try:
        return jsonify({"ok": True, "balance": SmsBower(key).balance()})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/api/start", methods=["POST"])
def api_start():
    w = _state.get("worker")
    if w and w["thread"].is_alive():
        return jsonify({"ok": False, "error": "已有运行中的任务"})

    d = request.json or {}
    count = int(d.get("count", 1))
    retries = int(d.get("retries", 2))
    cfg = _state["config"]
    _state["results"] = []

    stop_ev = threading.Event()
    thr = threading.Thread(
        target=_run, args=(cfg, count, retries, stop_ev), daemon=True
    )
    _state["worker"] = {"thread": thr, "stop": stop_ev, "status": "启动中", "phone": "", "progress": ""}
    thr.start()

    return jsonify({"ok": True})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    w = _state.get("worker")
    if w:
        w["stop"].set()
    return jsonify({"ok": True})


@app.route("/api/status")
def api_status():
    w = _state.get("worker")
    running = w["thread"].is_alive() if w else False
    return jsonify({
        "running": running,
        "worker_status": w["status"] if w else "",
        "results": [_sanitize_result(r) for r in _state["results"]],
    })


@app.route("/api/download")
def api_download():
    safe = [{k: v for k, v in r.items() if k != "access_token"}
            for r in _state["results"] if r.get("ok")]
    ts = time.strftime("%Y%m%d_%H%M%S")
    path = ROOT / f"results_{ts}.json"
    path.write_text(json.dumps(safe, indent=2, ensure_ascii=False), encoding="utf-8")
    return send_file(path, as_attachment=True, download_name=path.name)


@app.route("/api/log-since/<int:cursor>")
def api_log_since(cursor):
    lines = _state["log_lines"][cursor:]
    return jsonify({"lines": lines, "cursor": len(_state["log_lines"])})


# ============================================================
# iCloud Cookies 导入 & 储存
# ============================================================

@app.route("/api/icloud-cookies", methods=["GET", "POST"])
def api_icloud_cookies():
    if request.method == "POST":
        d = request.json or {}
        raw = d.get("cookies", "")
        if not raw.strip():
            return jsonify({"ok": False, "error": "cookies 为空"})

        # 尝试解析 JSON
        try:
            cookies = json.loads(raw)
        except json.JSONDecodeError as e:
            return jsonify({"ok": False, "error": f"JSON 解析失败: {e}"})

        # 写入本地文件
        COOKIES_FILE.write_text(json.dumps(cookies, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        _log(f"iCloud cookies 已保存 ({len(str(cookies))} bytes)", "success")
        return jsonify({"ok": True, "size": len(str(cookies))})

    # GET: 返回当前 cookies 状态
    if COOKIES_FILE.exists():
        try:
            cookies = json.loads(COOKIES_FILE.read_text(encoding="utf-8"))
            return jsonify({"ok": True, "loaded": True, "size": len(str(cookies)),
                            "preview": str(cookies)[:200]})
        except Exception:
            return jsonify({"ok": True, "loaded": False, "error": "文件存在但解析失败"})
    return jsonify({"ok": True, "loaded": False})


# ============================================================
# Worker
# ============================================================

class _WorkerLogIO:
    def __init__(self):
        self._buf = ""

    def write(self, s):
        self._buf += s
        while "\n" in self._buf:
            idx = self._buf.index("\n")
            line = self._buf[:idx].strip()
            self._buf = self._buf[idx + 1:]
            if line:
                _log(line, "info", 1)

    def flush(self):
        if self._buf.strip():
            _log(self._buf.strip(), "info", 1)
            self._buf = ""


def _run(config, count, retries, stop_event):
    cfg = dict(config)  # copy
    wid = 1
    _log(f"Worker 启动 (proxy={cfg.get('proxy','直连')})", "info", wid)

    w = _state.get("worker")
    if w: w["status"] = "启动中"

    import contextlib

    key = cfg.get("smsbower", {}).get("api_key", "")
    sms = SmsBower(key)
    try:
        _log(f"余额: {sms.balance()}", "info", wid)
    except Exception:
        pass

    ok_count = 0
    attempt = 0
    max_attempts = count * 15
    RESULTS_DIR.mkdir(exist_ok=True)
    _log(f"开始: 目标{count}个  重试{retries}次/步", "success", wid)

    sub = cfg.get("sub2api", {})
    bind_email = cfg.get("bind_email", "")

    # ── 获取 iCloud 邮箱 ──
    if not bind_email and sub.get("url"):
        with icloud_lock:
            try:
                cookies = _load_icloud_cookies()
                if cookies:
                    from icloud_hme import ICloudHME
                    ic = ICloudHME(cookies, verbose=False)
                    aliases = ic.list_aliases()
                    with _blacklist_lock:
                        bl_snapshot = set(_email_blacklist)
                    with _claimed_lock:
                        skip = bl_snapshot | _claimed_emails
                        reuse = next((a for a in aliases if a.get("active") and not a.get("used")
                                      and a["email"] not in skip), None)
                    if reuse:
                        bind_email = reuse["email"]
                        _log(f"复用iCloud别名: {bind_email}", "info", wid)
                    else:
                        bind_email = ic.create_alias()
                        _log(f"新iCloud别名: {bind_email}", "success", wid)
                    if bind_email:
                        with _claimed_lock:
                            _claimed_emails.add(bind_email)
                else:
                    _log("iCloud cookies 未导入，跳过邮箱", "warn", wid)
            except Exception as e:
                _log(f"iCloud失败: {e}", "error", wid)

    if bind_email:
        cfg["bind_email"] = bind_email
        if w: w["status"] = f"已获取邮箱: {bind_email}"

    # ── 注册循环 ──
    while ok_count < count and attempt < max_attempts and not stop_event.is_set():
        attempt += 1
        _log(f"第{attempt}次 [{ok_count}/{count}]", "info", wid)
        try:
            with contextlib.redirect_stdout(_WorkerLogIO()):
                result = ar.register_one(sms, cfg, verbose=True, step_retries=retries,
                                         create_account_max_retries=20,
                                         max_price=cfg.get("max_price", ""))
        except Exception as e:
            result = {"ok": False, "phone": "?", "error": str(e)}

        with _result_lock:
            _state["results"].append(result)

        if result["ok"]:
            ok_count += 1
            if w:
                w["status"] = f"✅ Phase1完成 ({ok_count}/{count})"
                w["phone"] = result.get("phone", "")
                w["progress"] = f"{ok_count}/{count}"
            _log(f"成功: {result['phone']} -> {bind_email}", "success", wid)

            # ── Phase 2: OAuth + 绑邮箱 + 上传 ──
            phase2_ok = True
            if sub.get("url") and sub.get("email") and result.get("session_token") and bind_email:
                if w: w["status"] = "🔄 Phase2: OAuth绑邮箱"
                _log("=== Phase 2: OAuth + 绑邮箱 + 上传 ===", "info", wid)
                phase2_ok = False
                try:
                    import requests as _r
                    import urllib.parse as _up

                    _log("  [1/4] 登录 SUB2API ...", "info", wid)
                    r = _r.post(f"{sub['url']}/api/v1/auth/login",
                                json={"email": sub["email"], "password": sub.get("pwd", "")}, timeout=15)
                    login_data = r.json()
                    if login_data.get("code") != 0:
                        raise RuntimeError(f"SUB2API登录失败: {login_data.get('message','?')}")
                    admin_token = login_data["data"]["access_token"]

                    _log("  [2/4] 获取 OAuth URL ...", "info", wid)
                    r = _r.post(f"{sub['url']}/api/v1/admin/openai/generate-auth-url",
                                json={"redirect_uri": "http://localhost:1455/auth/callback"},
                                headers={"Authorization": f"Bearer {admin_token}"}, timeout=30)
                    oauth_data = r.json()
                    if oauth_data.get("code") != 0:
                        raise RuntimeError(f"获取OAuth URL失败: {oauth_data.get('message','?')}")
                    oauth_url = oauth_data["data"]["auth_url"]
                    session_id = oauth_data["data"]["session_id"]
                    oauth_state = _up.parse_qs(_up.urlparse(oauth_url).query).get("state", [""])[0]

                    _log("  [3/4] OAuth流程: 登录->绑邮箱->验证->同意->code ...", "info", wid)
                    from openai_bind_email import run_second_half

                    _max_phase2_retries = 3
                    _phase2_try = 0
                    oauth_result = None
                    _current_email = bind_email

                    while _phase2_try < _max_phase2_retries:
                        _phase2_try += 1

                        if _phase2_try >= _max_phase2_retries:
                            with icloud_lock:
                                try:
                                    cookies = _load_icloud_cookies()
                                    if cookies:
                                        from icloud_hme import ICloudHME
                                        ic2 = ICloudHME(cookies, verbose=False)
                                        _current_email = ic2.create_alias()
                                        _log(f"  [3/4] 最终重试，创建新别名: {_current_email}", "success", wid)
                                        bind_email = _current_email
                                        cfg["bind_email"] = _current_email
                                        if _current_email:
                                            with _claimed_lock:
                                                _claimed_emails.add(_current_email)
                                except Exception as e2:
                                    _log(f"  [3/4] 创建新别名失败: {e2}", "error", wid)

                        if _phase2_try > 1:
                            _log(f"  [3/4] Phase2 重试 {_phase2_try}/{_max_phase2_retries}", "warn", wid)

                        oauth_result = run_second_half(
                            oauth_url=oauth_url,
                            phone=result["phone"],
                            password=result["password"],
                            icloud_email=_current_email,
                            icloud_cookies={},
                            imap_user=cfg.get("icloud", {}).get("user", ""),
                            imap_password=cfg.get("icloud", {}).get("pass", ""),
                            sub2api_url=sub["url"],
                            sub2api_email=sub["email"],
                            sub2api_password=sub.get("pwd", ""),
                            proxy=cfg.get("proxy", ""),
                            verbose=True,
                            sub2api_session_id=session_id,
                            sub2api_state=oauth_state,
                            sub2api_proxy_id=int(cfg.get("sub2api", {}).get("proxy_id", 0) or 0),
                        )
                        if oauth_result.get("ok"):
                            break
                        err = oauth_result.get("error", "")
                        if "email_already_in_use" in err:
                            _log(f"  [3/4] 邮箱已被占用: {_current_email}", "warn", wid)
                            if _current_email:
                                with _blacklist_lock:
                                    _email_blacklist.add(_current_email)
                                _save_email_blacklist()
                            with icloud_lock:
                                try:
                                    cookies = _load_icloud_cookies()
                                    if cookies:
                                        from icloud_hme import ICloudHME
                                        ic2 = ICloudHME(cookies, verbose=False)
                                        aliases = ic2.list_aliases()
                                        with _blacklist_lock:
                                            bl_snap = set(_email_blacklist)
                                        with _claimed_lock:
                                            skip = bl_snap | _claimed_emails
                                            reuse = next((a for a in aliases if a.get("active")
                                                          and a["email"] not in skip), None)
                                        if reuse:
                                            _current_email = reuse["email"]
                                        else:
                                            _current_email = ic2.create_alias()
                                        bind_email = _current_email
                                        cfg["bind_email"] = _current_email
                                        if _current_email:
                                            with _claimed_lock:
                                                _claimed_emails.add(_current_email)
                                    else:
                                        break
                                except Exception as e2:
                                    _log(f"  [3/4] 换邮箱失败: {e2}", "error", wid)
                                    break
                        else:
                            _err_lower = err.lower()
                            if any(kw in _err_lower for kw in ("ssl", "connection", "timeout", "proxy", "eof")):
                                _log(f"  [3/4] 网络波动, 5s后重试", "warn", wid)
                                time.sleep(5)
                            else:
                                break

                    if oauth_result and oauth_result.get("ok"):
                        phase2_ok = True
                        aid = oauth_result.get("sub2api_account_id", "?")
                        if w: w["status"] = f"✅ 完成 SUB2API#{aid}"
                        _log(f"  [4/4] 上传成功! SUB2API id={aid}", "success", wid)
                        result["sub2api_id"] = aid
                    else:
                        if w: w["status"] = "❌ Phase2失败"
                        _log(f"  [4/4] OAuth失败: {oauth_result.get('error','?') if oauth_result else 'no result'}", "error", wid)
                except Exception as e:
                    _log(f"Phase 2 error: {e}", "error", wid)

            _save_result(result, cfg)
        else:
            _log(f"失败: {result.get('phone','?')} {result.get('error','')}", "error", wid)

    tag = "success" if ok_count >= count else "warn"
    if w:
        w["status"] = f"{'✅' if ok_count>=count else '⚠️'} 结束 {ok_count}/{count}"
    _log(f"完成: {ok_count}/{count}", tag, wid)


# ============================================================
# Helpers
# ============================================================

def _load_icloud_cookies():
    """加载本地储存的 iCloud cookies"""
    if COOKIES_FILE.exists():
        try:
            return json.loads(COOKIES_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return None


def _save_config_file(cfg: dict):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _save_result(result: dict, config: dict):
    if not result.get("ok"):
        return
    safe = dict(result)
    safe["bind_email"] = config.get("bind_email", "")
    ts = time.strftime("%Y%m%d_%H%M%S")
    phone = result.get("phone", "unknown").replace("+", "")
    path = RESULTS_DIR / f"{phone}_{ts}.json"
    path.write_text(json.dumps(safe, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    all_path = RESULTS_DIR / "_all.json"
    with _result_lock:
        all_results = []
        if all_path.exists():
            try:
                all_results = json.loads(all_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        all_results.append(safe)
        all_path.write_text(json.dumps(all_results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _sanitize_config(cfg):
    return copy.deepcopy(cfg)


def _sanitize_result(r):
    r2 = dict(r)
    for k in ["session_token", "access_token"]:
        if r2.get(k): r2[k] = r2[k][:30] + "..."
    return r2


def start_gui(host="0.0.0.0", port=8080):
    print(f"http://127.0.0.1:{port}")
    app.run(host=host, port=port, debug=False, threaded=True)


# ============================================================
# HTML
# ============================================================

_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ChatGPT Auto Register</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI','Microsoft YaHei',sans-serif;background:#fdf6e3;color:#5c4b3b;display:flex;height:100vh}
.sidebar{width:320px;background:#f5e6d3;border-right:1px solid #e0cda7;padding:16px;overflow-y:auto;display:flex;flex-direction:column}
.main{flex:1;display:flex;flex-direction:column}
.log{flex:1;background:#fef8f0;padding:10px 14px;overflow-y:auto;overflow-x:hidden;font:13px/1.6 Consolas,'Microsoft YaHei',monospace;border-top:1px solid #e8d5b0;word-break:break-all}
.log .info{color:#8b5e3c}.log .success{color:#2e7d32}.log .error{color:#c62828}.log .warn{color:#e65100}
.log .time{color:#aaa;margin-right:6px}
.log-toolbar{display:flex;align-items:center;gap:8px;padding:4px 14px;background:#f5e6d3;border-top:1px solid #e0cda7;font-size:12px}
.toast{position:fixed;top:12px;right:12px;padding:8px 16px;border-radius:4px;font-size:13px;z-index:999;opacity:0;transition:opacity .3s}
.toast.show{opacity:1}.toast-ok{background:#c8e6c9;color:#2e7d32}.toast-err{background:#ffcdd2;color:#c62828}
h2{font-size:15px;margin-bottom:10px;color:#6b4226}
label{display:block;font-size:11px;margin:6px 0 2px;color:#8b6f4e}
input,select,textarea{width:100%;padding:6px 8px;background:#fffbf5;border:1px solid #d4b896;border-radius:4px;color:#5c4b3b;font-size:13px}
input:focus,select:focus,textarea:focus{outline:none;border-color:#c4820e;box-shadow:0 0 0 2px rgba(196,130,14,.15)}
textarea{resize:vertical;font-family:Consolas,'Microsoft YaHei',monospace;font-size:11px}
button{padding:8px 16px;border:none;border-radius:4px;cursor:pointer;font-size:13px;margin:4px 2px;transition:all .15s}
button:disabled{opacity:.5;cursor:not-allowed}
.btn-start{background:#c4820e;color:#fff}.btn-start:hover:not(:disabled){background:#a86e0c}
.btn-stop{background:#c62828;color:#fff}.btn-stop:hover:not(:disabled){background:#b71c1c}
.btn-neutral{background:#f0e4d0;color:#5c4b3b;border:1px solid #d4b896}
.btn-neutral:hover:not(:disabled){background:#e6d5b8}
.btn-row{display:flex;gap:4px;margin:6px 0}
.stats{display:flex;gap:12px;margin:8px 0;font-size:12px}
.stat{flex:1;padding:8px;background:#fffbf5;border:1px solid #e8d5b0;border-radius:4px;text-align:center}
.stat .val{display:block;font-size:18px;font-weight:bold;color:#8b5e3c;margin-top:2px}
.stat .lbl{color:#8b6f4e;font-size:11px}
.spin{display:inline-block;width:12px;height:12px;border:2px solid #ddd;border-top-color:#c4820e;border-radius:50%;animation:s .6s linear infinite;margin-right:4px}
@keyframes s{to{transform:rotate(360deg)}}
details{font-size:12px}
summary{cursor:pointer;color:#8b6f4e;margin-bottom:6px}
hr{border-color:#e0cda7;margin:8px 0}
.worker-status{font-size:11px;color:#8b6f4e;margin-top:6px;text-align:center}
</style></head><body>
<div class="sidebar">
  <h2>ChatGPT Auto Register</h2>

  <label>SMSBower Key</label>
  <input id="api_key" placeholder="your-smsbower-key">

  <label>代理</label>
  <input id="proxy" placeholder="socks5h://127.0.0.1:10808">

  <label>国家代码</label>
  <input id="country" value="151">

  <label>最高价格 (空=不限)</label>
  <input id="max_price" placeholder="0.039">

  <label>密码 (留空=随机)</label>
  <input id="password" placeholder="留空=随机">

  <label>验证码超时(秒)</label>
  <input id="sms_timeout" value="30" type="number">

  <label>目标数量</label>
  <input id="count" value="1" type="number" min="1" max="99">

  <label>步骤重试</label>
  <input id="retries" value="2" type="number" min="0" max="10">

  <details style="margin-top:10px">
    <summary>iCloud 邮箱 &amp; SUB2API</summary>
    <label>iCloud 邮箱 (IMAP)</label>
    <input id="imap_user" placeholder="xxx@icloud.com">
    <label>Apple 专用密码</label>
    <input id="imap_pass" type="password" placeholder="">
    <label>SUB2API 地址</label>
    <input id="sub2api_url" placeholder="http://xxx:8003">
    <label>SUB2API 管理邮箱</label>
    <input id="sub2api_email" placeholder="admin@xxx.com">
    <label>SUB2API 管理密码</label>
    <input id="sub2api_pwd" type="password" placeholder="">
    <label>绑定邮箱 (手动指定)</label>
    <input id="bind_email" placeholder="alias@icloud.com">
  </details>

  <details style="margin-top:6px">
    <summary>iCloud Cookies 导入</summary>
    <label>粘贴 cookies JSON</label>
    <textarea id="cookies_input" rows="6" placeholder='[{"name":"X-APPLE-WEB...", ...}]'></textarea>
    <div class="btn-row">
      <button class="btn-neutral" onclick="importCookies()">导入 Cookies</button>
      <span id="cookies_status" style="font-size:11px;color:#8b6f4e;line-height:2.4"></span>
    </div>
  </details>

  <div class="btn-row" style="margin-top:10px">
    <button class="btn-neutral" id="btn-balance" onclick="checkBalance()">查余额</button>
    <button class="btn-neutral" onclick="saveConfig()">保存配置</button>
  </div>
  <div class="btn-row">
    <button class="btn-start" id="btn-start" onclick="startReg()" style="flex:1">开始注册</button>
    <button class="btn-stop" id="btn-stop" onclick="stopReg()" disabled>停止</button>
  </div>

  <div class="stats">
    <div class="stat"><span class="lbl">余额</span><span class="val" id="balance">-</span></div>
    <div class="stat"><span class="lbl">成功</span><span class="val" id="ok-count">0</span></div>
    <div class="stat"><span class="lbl">失败</span><span class="val" id="fail-count">0</span></div>
  </div>
  <div class="btn-row">
    <button class="btn-neutral" onclick="downloadResults()" style="width:100%">下载结果</button>
  </div>
  <div class="worker-status" id="worker-status">就绪</div>
</div>
<div class="main">
  <div class="log" id="log"><div class="info">等待启动...</div></div>
  <div class="log-toolbar">
    <label><input type="checkbox" id="auto-scroll" checked>自动滚动</label>
    <span style="flex:1"></span>
    <button class="btn-neutral" onclick="clearLog()" style="font-size:11px;padding:2px 8px">清空</button>
  </div>
</div>
<div class="toast" id="toast"></div>

<script>
function G(id){return document.getElementById(id);}
function toast(msg,ok){var t=G('toast');t.textContent=msg;t.className='toast '+(ok?'toast-ok':'toast-err')+' show';setTimeout(function(){t.className='toast'},2500);}

var logEl=G('log'),logCursor=0;

function pollLog(){
  fetch('/api/log-since/'+logCursor).then(function(r){return r.json()}).then(function(d){
    if(d.lines.length>0){
      d.lines.forEach(function(item){
        var div=document.createElement('div');
        div.innerHTML='<span class=time>'+item.time+'</span>'+item.msg;
        div.className=item.tag||'info';
        logEl.appendChild(div);
      });
      if(G('auto-scroll').checked)logEl.scrollTop=logEl.scrollHeight;
      if(logEl.children.length>500){for(var i=0;i<100;i++)logEl.removeChild(logEl.firstChild);}
    }
    logCursor=d.cursor;
  });
}
setInterval(pollLog,800);

function saveConfig(){
  var d={api_key:G('api_key').value,proxy:G('proxy').value,country:G('country').value,
    password:G('password').value,max_price:G('max_price').value,
    sms_timeout:G('sms_timeout').value,
    imap_user:G('imap_user').value,imap_pass:G('imap_pass').value,
    sub2api_url:G('sub2api_url').value,sub2api_email:G('sub2api_email').value,
    sub2api_pwd:G('sub2api_pwd').value,bind_email:G('bind_email').value};
  return fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)})
    .then(function(r){return r.json()}).then(function(j){toast('配置已保存',j.ok);return j;});
}

function checkBalance(){
  var btn=G('btn-balance');var orig=btn.textContent;btn.disabled=true;btn.innerHTML='<span class=spin></span>查询中';
  fetch('/api/balance').then(function(r){return r.json()}).then(function(j){
    if(j.ok){G('balance').textContent=j.balance.replace('ACCESS_BALANCE:','');toast('余额: '+j.balance.replace('ACCESS_BALANCE:',''),true);}
    else{toast('查询失败: '+j.error,false);}
    btn.disabled=false;btn.textContent=orig;
  }).catch(function(){btn.disabled=false;btn.textContent=orig;toast('网络错误',false);});
}

function startReg(){
  saveConfig().then(function(){
    G('btn-start').disabled=true;G('btn-stop').disabled=false;G('worker-status').innerHTML='<span class=spin></span>运行中';
    G('ok-count').textContent='0';G('fail-count').textContent='0';
    var d={count:parseInt(G('count').value)||1,retries:parseInt(G('retries').value)||2};
    fetch('/api/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(d)})
      .then(function(r){return r.json()}).then(function(j){if(!j.ok)toast(j.error,false);});
  });
}

function stopReg(){
  G('btn-stop').disabled=true;
  fetch('/api/stop',{method:'POST'}).then(function(){toast('正在停止...',true);});
}

function downloadResults(){window.open('/api/download');}
function clearLog(){var l=G('log');while(l.children.length>1)l.removeChild(l.firstChild);}

function importCookies(){
  var raw=G('cookies_input').value.trim();
  if(!raw){toast('请粘贴 cookies JSON',false);return;}
  var btn=event.target;btn.disabled=true;btn.textContent='导入中...';
  fetch('/api/icloud-cookies',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cookies:raw})})
    .then(function(r){return r.json()}).then(function(j){
      btn.disabled=false;btn.textContent='导入 Cookies';
      if(j.ok){
        G('cookies_status').textContent='已导入 ('+j.size+' bytes)';
        G('cookies_status').style.color='#2e7d32';
        toast('Cookies 已导入',true);
      }else{
        G('cookies_status').textContent=j.error;
        G('cookies_status').style.color='#c62828';
        toast(j.error,false);
      }
    }).catch(function(){btn.disabled=false;btn.textContent='导入 Cookies';toast('网络错误',false);});
}

function loadCookiesStatus(){
  fetch('/api/icloud-cookies').then(function(r){return r.json()}).then(function(j){
    if(j.ok && j.loaded){
      G('cookies_status').textContent='已加载 ('+j.size+' bytes)';
      G('cookies_status').style.color='#2e7d32';
    }else{
      G('cookies_status').textContent='未导入';
      G('cookies_status').style.color='#8b6f4e';
    }
  });
}

function pollStatus(){
  fetch('/api/status').then(function(r){return r.json()}).then(function(j){
    var running=j.running;
    G('btn-start').disabled=running;G('btn-stop').disabled=!running;
    if(running){
      G('worker-status').innerHTML='<span class=spin></span>'+j.worker_status;
    }else if(j.worker_status.indexOf('结束')>=0||j.worker_status.indexOf('✅')>=0||j.worker_status.indexOf('⚠️')>=0){
      G('worker-status').textContent=j.worker_status;
    }else if(G('worker-status').innerHTML.indexOf('spin')>=0){
      G('worker-status').textContent='就绪';
    }
    var ok=j.results.filter(function(x){return x.ok;});
    G('ok-count').textContent=ok.length;G('fail-count').textContent=j.results.length-ok.length;
  });
}
setInterval(pollStatus,2000);

function loadConfig(){
  fetch('/api/config').then(function(r){return r.json()}).then(function(j){
    if(!j.ok)return;
    var c=j.config;
    if(c.smsbower) G('api_key').value=c.smsbower.api_key||'';
    G('proxy').value=c.proxy||'';
    G('country').value=c.country||'151';
    G('max_price').value=c.max_price||'';
    G('sms_timeout').value=c.sms_timeout||'30';
    if(c.register) G('password').value=c.register.password||'';
    if(c.icloud){
      G('imap_user').value=c.icloud.user||'';
      G('imap_pass').value=c.icloud.pass||'';
    }
    if(c.sub2api){
      G('sub2api_url').value=c.sub2api.url||'';
      G('sub2api_email').value=c.sub2api.email||'';
      G('sub2api_pwd').value=c.sub2api.pwd||'';
    }
    G('bind_email').value=c.bind_email||'';
    checkBalance();
  });
}

loadConfig();
loadCookiesStatus();
</script></body></html>"""

if __name__ == "__main__":
    start_gui()
