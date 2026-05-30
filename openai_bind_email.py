#!/usr/bin/env python3
"""
OpenAI 后半段 — 纯协议版（基于真实抓包端点）

真实流程:
  [1] POST /oauth/authorize          Cloudflare 挑战 → 302
  [2] POST sentinel/req              flow=authorize_continue → oai-sc
  [3] POST /api/accounts/authorize/continue  {"username":{"kind":"phone_number","value":"+56..."}}
  [4] POST sentinel/req              flow=password_verify
  [5] POST /api/accounts/password/verify     {"password":"xxx"}
  [6] POST /api/accounts/add-email/send      {"email":"...@icloud.com"}
  [7] iCloud 收绑定验证码
  [8] POST /api/accounts/email-otp/validate  {"code":"796880"}
  [9] POST /api/accounts/workspace/select    {"workspace_id":"xxx"}
  [10] GET  /api/oauth/oauth2/auth?login_verifier=xxx  → 302 → code
  [11] code → token 交换 + SUB2API 上传
"""

import re
import json
import time
import uuid
import urllib3
from typing import Optional, Dict, Any, Tuple, Callable
from urllib.parse import urlparse, parse_qs, urljoin

from curl_cffi import requests as curl_requests

urllib3.disable_warnings()

AUTH = "https://auth.openai.com"
SENTINEL = "https://sentinel.openai.com/backend-api/sentinel/req"
CHATGPT = "https://chatgpt.com"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
)

JSON_HEADERS = {
    "accept": "application/json",
    "accept-language": "en-US,en;q=0.9",
    "content-type": "application/json",
    "origin": AUTH,
    "user-agent": UA,
    "sec-ch-ua": '"Google Chrome";v="145"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
}

PAGE_HEADERS = {
    "accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.9",
    "user-agent": UA,
}


def _log(msg: str):
    print(f"  [AUTH] {msg}")


# ============================================================
# Sentinel PoW (简化版，内联用)
# ============================================================

class _Sentinel:
    """内联 Sentinel，避免额外依赖"""

    MAX_ATTEMPTS = 500000

    def __init__(self, device_id: str):
        self.device_id = device_id
        self.sid = str(uuid.uuid4())
        self.user_agent = UA

    @staticmethod
    def _fnv1a_32(text: str) -> str:
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= h >> 16
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= h >> 16
        return format(h & 0xFFFFFFFF, "08x")

    def _config(self) -> list:
        import random
        perf = random.uniform(1000, 50000)
        return [
            "1920x1080",
            time.strftime("%a %b %d %Y %H:%M:%S GMT+0000", time.gmtime()),
            4294705152, random.random(), self.user_agent,
            "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js",
            None, None, "en-US", random.random(),
            random.choice(["plugins-undefined", "mimeTypes-undefined"]),
            random.choice(["location", "documentURI"]),
            random.choice(["Object", "parseFloat"]),
            perf, self.sid, "",
            random.choice([4, 8, 12, 16]),
            time.time() * 1000 - perf,
        ]

    def _b64(self, data) -> str:
        import base64
        return base64.b64encode(
            json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode()
        ).decode()

    def _requirements(self) -> str:
        d = self._config()
        d[3] = 1
        d[9] = 5
        return "gAAAAAC" + self._b64(d)

    def _pow(self, seed: str, difficulty: str) -> str:
        import random
        diff = str(difficulty or "0")
        t0 = time.time()
        for i in range(self.MAX_ATTEMPTS):
            d = self._config()
            d[3] = i
            d[9] = round((time.time() - t0) * 1000)
            p = self._b64(d)
            if self._fnv1a_32(seed + p)[:len(diff)] <= diff:
                return "gAAAAAB" + p + "~S"
        return "gAAAAAB" + "wQ8Lk5F" * 10 + self._b64(str(None))

    def get(self, session, flow: str) -> str:
        r = session.post(
            SENTINEL,
            data=json.dumps({"p": self._requirements(), "id": self.device_id, "flow": flow}),
            headers={
                "Content-Type": "text/plain;charset=UTF-8",
                "Origin": "https://sentinel.openai.com",
                "User-Agent": self.user_agent,
            },
            verify=False, timeout=30,
        )
        if not r.ok:
            return ""
        data = r.json()
        token = str(data.get("token") or "")
        if not token:
            return ""
        pw = data.get("proofofwork") or {}
        if pw.get("required") and pw.get("seed"):
            p = self._pow(str(pw["seed"]), str(pw.get("difficulty", "0")))
        else:
            p = self._requirements()
        return json.dumps({"p": p, "t": "", "c": token, "id": self.device_id, "flow": flow})


# ============================================================
# 后半段引擎 (真实端点)
# ============================================================

class OAuthSecondHalf:
    """OpenAI OAuth 后半段 — 真实端点版"""

    def __init__(self, proxy: str = "", verbose: bool = True, device_id: str = ""):
        self.verbose = verbose
        self.device_id = device_id or str(uuid.uuid4())
        self._default_timeout = 30

        if proxy:
            import requests as r
            self.session = r.Session()
            self.session.proxies = {"http": proxy, "https": proxy}
            self.session.verify = False
            # Inject default timeout so proxy hangs don't block forever
            _orig = self.session.request
            def _req(method, url, **kw):
                kw.setdefault("timeout", self._default_timeout)
                return _orig(method, url, **kw)
            self.session.request = _req
        else:
            self.session = curl_requests.Session(impersonate="chrome", verify=False)

        self.sentinel = _Sentinel(self.device_id)
        self._sentinel_cache: Dict[str, str] = {}

    def _l(self, msg): 
        if self.verbose: _log(msg)

    def _sentinel_token(self, flow: str) -> str:
        if flow not in self._sentinel_cache:
            try:
                self._sentinel_cache[flow] = self.sentinel.get(self.session, flow)
            except Exception as e:
                self._l(f"Sentinel 跳过 ({flow}): {e}")
                self._sentinel_cache[flow] = ""
        return self._sentinel_cache[flow]

    # ---------- 解析 OAuth URL ----------

    @staticmethod
    def parse_oauth_url(oauth_url: str) -> Dict[str, str]:
        parsed = urlparse(oauth_url)
        return {k: v[0] for k, v in parse_qs(parsed.query).items()}

    # ---------- [1] 发起 OAuth + Cloudflare ----------

    def initiate_oauth(self, oauth_url: str):
        """
        ① GET oauth_url → 跟重定向到登录页
        """
        self._l("[1] 发起 OAuth (GET) ...")
        r = self.session.get(
            oauth_url,
            headers={
                **PAGE_HEADERS,
                "sec-fetch-site": "cross-site",
                "sec-fetch-mode": "navigate",
            },
            allow_redirects=True,
        )
        url = r.url
        html = r.text
        is_error = "/error" in url
        self._l(f"[1] 当前 URL: {url[:120]}")
        if is_error:
            self._l(f"[1] 重定向到了错误页!")
        return not is_error, url, html

    # ---------- [2] Sentinel authorize_continue ----------

    def sentinel_authorize(self) -> str:
        self._l("[2] Sentinel (authorize_continue) ...")
        return self._sentinel_token("authorize_continue")

    # ---------- [3] 提交手机号 ----------

    def submit_phone(self, phone: str) -> Dict:
        """
        [3] POST /api/accounts/authorize/continue
           {"username":{"kind":"phone_number","value":"+56947125968"}}
        返回: {continue_url, page:{type, payload}}
        设置: oai-client-auth-session cookie
        """
        self._l(f"[3] 提交手机号: {phone}")
        h = dict(JSON_HEADERS)
        st = self._sentinel_token("authorize_continue")
        if st:
            h["OpenAI-Sentinel-Token"] = st
        r = self.session.post(
            f"{AUTH}/api/accounts/authorize/continue",
            json={"username": {"kind": "phone_number", "value": phone}},
            headers=h,
        )
        self._l(f"[3] 响应: {r.status_code}")
        return r.json() if r.ok else {"error": r.text}

    # ---------- [4] Sentinel password_verify ----------

    def sentinel_password(self) -> str:
        self._l("[4] Sentinel (password_verify) ...")
        return self._sentinel_token("password_verify")

    # ---------- [5] 验证密码 ----------

    def verify_password(self, password: str) -> Dict:
        """
        [5] POST /api/accounts/password/verify
           {"password":"xxx"}
        返回: {continue_url:"/add-email", page:{type:"add_email"}}
        """
        self._l("[5] 验证密码 ...")
        h = dict(JSON_HEADERS)
        st = self._sentinel_token("password_verify")
        if st:
            h["OpenAI-Sentinel-Token"] = st
        r = self.session.post(
            f"{AUTH}/api/accounts/password/verify",
            json={"password": password},
            headers=h,
        )
        data = r.json() if r.ok else {"error": r.text}
        pt = (data.get("page") or {}).get("type", "")
        self._l(f"[5] 响应: page={pt}")
        return data

    # ---------- [6] 发送绑定邮箱 ----------

    def send_bind_email(self, email: str) -> Dict:
        """
        [6] POST /api/accounts/add-email/send
           {"email":"botch.sear_8w@icloud.com"}
        返回: {continue_url:"/email-verification", page:{type:"email_otp_verification"}}
        """
        self._l(f"[6] 发送绑定邮箱: {email}")
        h = dict(JSON_HEADERS)
        st = self._sentinel_token("password_verify")
        if st:
            h["OpenAI-Sentinel-Token"] = st
        r = self.session.post(
            f"{AUTH}/api/accounts/add-email/send",
            json={"email": email},
            headers=h,
        )
        data = r.json() if r.ok else {"error": r.text}
        pt = (data.get("page") or {}).get("type", "")
        self._l(f"[6] 响应: page={pt}")
        return data

    # ---------- [7] 验证邮箱 OTP ----------

    def verify_email_otp(self, code: str) -> Dict:
        """
        [7] POST /api/accounts/email-otp/validate
           {"code":"796880"}
        返回: {continue_url:"/sign-in-with-chatgpt/codex/consent", page:{type:"consent"}}
        email 标记为 verified
        """
        self._l(f"[7] 验证邮箱 OTP: {code}")
        h = dict(JSON_HEADERS)
        r = self.session.post(
            f"{AUTH}/api/accounts/email-otp/validate",
            json={"code": code},
            headers=h,
        )
        data = r.json() if r.ok else {"error": r.text}
        pt = (data.get("page") or {}).get("type", "")
        self._l(f"[7] 响应: page={pt}")
        return data

    # ---------- [8] 查询 session 状态 ----------

    def get_session_dump(self) -> Dict:
        """
        GET /api/accounts/client_auth_session_dump
        返回: {client_auth_session:{session_id, username, email, workspaces, ...}}
        """
        r = self.session.get(
            f"{AUTH}/api/accounts/client_auth_session_dump",
            headers=JSON_HEADERS,
        )
        return r.json() if r.ok else {}

    # ---------- [9] 选择工作区 ----------

    def select_workspace(self, workspace_id: str) -> Dict:
        """
        [9] POST /api/accounts/workspace/select
           {"workspace_id":"74461035-..."}
        返回: {continue_url:"...login_verifier...", page:{...}}
        """
        self._l(f"[9] 选择工作区: {workspace_id}")
        r = self.session.post(
            f"{AUTH}/api/accounts/workspace/select",
            json={"workspace_id": workspace_id},
            headers=JSON_HEADERS,
        )
        data = r.json() if r.ok else {"error": r.text}
        return data

    # ---------- [10] 最终 OAuth → 获取 code ----------

    def follow_continue_until_code(self, continue_url: str, max_hops: int = 8) -> Optional[str]:
        """
        跟随 continue_url 链，直到捕获 redirect_uri 中的 code
        会自动处理 consent 页（获取 session_dump → 选 workspace → 再跟）
        """
        url = continue_url
        for hop in range(max_hops):
            self._l(f"[10] hop {hop+1}/{max_hops}: {url[:100]}...")
            r = self.session.get(
                url if url.startswith("http") else urljoin(AUTH, url),
                headers={**PAGE_HEADERS, "referer": AUTH, "sec-fetch-site": "same-origin"},
                allow_redirects=False,
            )
            location = r.headers.get("Location", "")
            ct = r.headers.get("content-type", "")
            self._l(f"[10]   -> {r.status_code} ct={ct[:30]} loc={location if location else 'none'}")

            # 检查 Location / URL 中的 code
            if location:
                parsed = urlparse(location)
                code = parse_qs(parsed.query).get("code", [None])[0]
                if code:
                    self._l(f"[10] code: {code[:30]}...")
                    return code
                url = location if location.startswith("http") else urljoin(AUTH, location)
                continue

            # 当前 URL 中的 code
            parsed = urlparse(r.url)
            code = parse_qs(parsed.query).get("code", [None])[0]
            if code:
                self._l(f"[10] code (url): {code[:30]}...")
                return code

            # HTML consent 页 → 需要选 workspace
            if "text/html" in ct and ("consent" in url.lower() or "consent" in r.text.lower()[:500]):
                self._l("[10] consent 页 → 选 workspace ...")
                dump = self.get_session_dump()
                workspaces = ((dump.get("client_auth_session") or {}).get("workspaces") or [])
                if workspaces:
                    ws_id = workspaces[0].get("id", "")
                    self._l(f"[10] workspace: {ws_id}")
                    ws_r = self.select_workspace(ws_id)
                    next_url = ws_r.get("continue_url", "")
                    if next_url:
                        url = next_url if next_url.startswith("http") else urljoin(AUTH, next_url)
                        continue
                # 回退：尝试从 HTML 提取 form
                action, fields = _extract_form(r.url, r.text)
                if action and fields:
                    self._l(f"[10] POST consent form: {action}")
                    fr = self._post_form(action, fields)
                    loc = fr.headers.get("Location", "")
                    if loc:
                        url = loc if loc.startswith("http") else urljoin(AUTH, loc)
                        continue

            # JSON → 提取 continue_url
            if "json" in ct:
                try:
                    data = r.json()
                    next_url = data.get("continue_url", "")
                    if next_url:
                        url = next_url if next_url.startswith("http") else urljoin(AUTH, next_url)
                        continue
                except Exception:
                    pass

            break

        return None

    def final_oauth(self, oauth_params: Dict[str, str]) -> Optional[str]:
        """
        [10] GET /api/oauth/oauth2/auth?client_id=...&login_verifier=...&...
           → 302 → redirect_uri?code=xxx&state=yyy
        返回: authorization code
        """
        self._l("[10] 最终 OAuth → 获取 code ...")

        # 构建完整参数
        params = dict(oauth_params)
        # 从 URL 拼接
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"{AUTH}/api/oauth/oauth2/auth?{qs}"

        r = self.session.get(
            url,
            headers={**PAGE_HEADERS, "referer": AUTH},
            allow_redirects=False,
        )

        # 从 Location header 提取 code
        location = r.headers.get("Location", "")
        if location:
            parsed = urlparse(location)
            code = parse_qs(parsed.query).get("code", [None])[0]
            if code:
                self._l(f"[10] code: {code[:30]}...")
                return code

        # 跟随重定向后从 URL 提取
        r2 = self.session.get(
            url,
            headers={**PAGE_HEADERS, "referer": AUTH},
            allow_redirects=True,
        )
        parsed = urlparse(r2.url)
        code = parse_qs(parsed.query).get("code", [None])[0]
        if code:
            self._l(f"[10] code: {code[:30]}...")
            return code

        self._l("[10] 未捕获到 code")
        return None


# ============================================================
# 完整后半段入口
# ============================================================

def run_second_half(
    oauth_url: str,
    phone: str,
    password: str,
    icloud_email: str,
    icloud_cookies: Dict[str, str],
    sub2api_url: str = "",
    sub2api_email: str = "",
    sub2api_password: str = "",
    sub2api_proxy_id: int = 0,
    proxy: str = "",
    verbose: bool = True,
    bind_code: str = "",
    imap_user: str = "",
    imap_password: str = "",
    sub2api_session_id: str = "",
    sub2api_state: str = "",
) -> Dict:
    """
    完整后半段 (基于真实端点):

    [1] POST /oauth/authorize             发起OAuth
    [2] sentinel/req (authorize_continue) 安全检测
    [3] /api/accounts/authorize/continue  提交手机号
    [4] sentinel/req (password_verify)    刷新安全token
    [5] /api/accounts/password/verify     验证密码
    [6] /api/accounts/add-email/send      绑定iCloud邮箱
    [7] iCloud收验证码
    [8] /api/accounts/email-otp/validate  验证邮箱OTP
    [9] /api/accounts/workspace/select    选择工作区
    [10] /api/oauth/oauth2/auth            → code
    [11] code→token + SUB2API上传
    """

    def log(msg):
        if verbose: _log(msg)

    flow = OAuthSecondHalf(proxy=proxy, verbose=verbose)

    try:
        # 解析 OAuth URL 参数
        oauth_params = OAuthSecondHalf.parse_oauth_url(oauth_url)
        log(f"OAuth params: client_id={oauth_params.get('client_id','?')[:20]}...")

        # ---- [1] 发起 OAuth ----
        log("=" * 40)
        ok, current_url, html = flow.initiate_oauth(oauth_url)
        if not ok:
            log(f"[1] OAuth 发起失败, URL: {current_url[:120]}")
            return {"ok": False, "error": f"initiate_oauth failed: {current_url[:120]}"}

        # ---- [2] Sentinel ----
        flow.sentinel_authorize()

        # ---- [3] 提交手机号 ----
        log("[3] 提交手机号 ...")
        r = flow.submit_phone(phone)
        if r.get("error"):
            log(f"[3] 失败: {r.get('error')}")
            return {"ok": False, "error": f"submit_phone: {r.get('error')}"}
        log(f"[3] page: {(r.get('page') or {}).get('type', '?')}")

        # ---- [4] Sentinel ----
        flow.sentinel_password()

        # ---- [5] 验证密码 ----
        log("[5] 验证密码 ...")
        r = flow.verify_password(password)
        if r.get("error"):
            log(f"[5] 失败: {r.get('error')}")
            return {"ok": False, "error": f"verify_password: {r.get('error')}"}
        page_type = (r.get("page") or {}).get("type", "")
        log(f"[5] page: {page_type}")

        # 分支判断
        if "about_you" in page_type:
            # 新号没填资料 → 先填资料
            log("[5] about_you 页, 先填资料 ...")
            h = dict(JSON_HEADERS)
            h["referer"] = f"{AUTH}/about-you"
            r = flow.session.post(
                f"{AUTH}/api/accounts/create_account",
                json={"name": "A", "birthdate": "2000-01-01"},
                headers=h,
                allow_redirects=False,
            )
            data = r.json() if r.ok else {"error": r.text}
            continue_url = data.get("continue_url", "")
            # 检查重定向
            location = r.headers.get("Location", "")
            if location:
                continue_url = location
            page_type = (data.get("page") or {}).get("type", "")
            log(f"[5] create_account page: {page_type}")
            # 资料填完后可能到 add_email
            if "consent" in page_type or "add_email" in page_type or "email_otp" in page_type:
                pass  # 继续走下面的分支
            else:
                code = flow.follow_continue_until_code(data.get("continue_url", "")) if data.get("continue_url") else None
                if not code:
                    code = flow.final_oauth(oauth_params)
                if not code:
                    return {"ok": False, "error": "no authorization code after about_you"}

        if "consent" in page_type:
            # 已到同意页 → 选工作区 → 拿 code
            log("[5] 已到 consent 页，跳过绑邮箱")
            dump = flow.get_session_dump()
            workspaces = ((dump.get("client_auth_session") or {}).get("workspaces") or [])
            if workspaces:
                ws_id = workspaces[0].get("id", "")
                log(f"[9] 工作区: {ws_id}")
                ws_r = flow.select_workspace(ws_id)
                log(f"[9] page: {(ws_r.get('page') or {}).get('type', '?')}")
                continue_url = ws_r.get("continue_url", "")
            else:
                continue_url = ""
            code = flow.follow_continue_until_code(continue_url) if continue_url else None
            if not code:
                code = flow.final_oauth(oauth_params)
            if not code:
                return {"ok": False, "error": "no authorization code"}

        elif "email_otp_verification" in page_type:
            # 先尝试发新的绑定邮件
            log("[5] email_otp_verification, 先发新邮箱 ...")
            if icloud_email:
                r_send = flow.send_bind_email(icloud_email)
                send_err = r_send.get("error", "")
                send_page = (r_send.get("page") or {}).get("type", "")
                log(f"[6] send result: error={send_err} page={send_page}")
                if not send_err and "otp_verification" in send_page:
                    log("[6] 新验证码已发送,等待IMAP...")

            code_bind = bind_code
            if not code_bind:
                log("[7] iCloud 收验证码 ...")
                from icloud_hme import ICloudHME
                icloud = ICloudHME(icloud_cookies or {}, verbose=verbose)
                code_bind = icloud.poll_mail_for_code(
                    target_email=icloud_email,
                    sender_filters=["openai", "noreply", "verification", "no-reply"],
                    timeout=60,
                    imap_user=imap_user,
                    imap_password=imap_password,
                )
                if not code_bind:
                    print(f"\n  [!] 自动轮询超时, 目标邮箱: {icloud_email}")
                    code_bind = input("  [?] 输入6位验证码: ").strip()
            if not code_bind:
                return {"ok": False, "error": "binding code timeout"}
            log(f"[7] 验证码: {code_bind}")

            # 验证 + workspace + 取 code
            r = flow.verify_email_otp(code_bind)
            if r.get("error"):
                log(f"[8] 失败: {r.get('error')}")
                return {"ok": False, "error": f"verify_email_otp: {r.get('error')}"}
            log(f"[8] page: {(r.get('page') or {}).get('type', '?')}")
            continue_url = r.get("continue_url", "")

            if not continue_url:
                dump = flow.get_session_dump()
                workspaces = ((dump.get("client_auth_session") or {}).get("workspaces") or [])
                if workspaces:
                    ws_id = workspaces[0].get("id", "")
                    ws_r = flow.select_workspace(ws_id)
                    continue_url = ws_r.get("continue_url", "")

            code = flow.follow_continue_until_code(continue_url) if continue_url else None
            if not code:
                code = flow.final_oauth(oauth_params)
            if not code:
                return {"ok": False, "error": "no authorization code"}

        else:
            # 需要绑定新邮箱 (add_email)
            log(f"[6] 绑定邮箱: {icloud_email} ...")
            r = flow.send_bind_email(icloud_email)
            if r.get("error"):
                log(f"[6] 失败: {r.get('error')}")
                return {"ok": False, "error": f"send_bind_email: {r.get('error')}"}
            log(f"[6] page: {(r.get('page') or {}).get('type', '?')}")

            # ---- [7] iCloud 收码 ----
            log("[7] iCloud 收验证码 ...")
            if bind_code:
                code_bind = bind_code
                log(f"[7] 使用手动验证码: {code_bind}")
            else:
                from icloud_hme import ICloudHME
                icloud = ICloudHME(icloud_cookies or {}, verbose=verbose)
                code_bind = icloud.poll_mail_for_code(
                    target_email=icloud_email,
                    sender_filters=["openai", "noreply", "verification", "no-reply"],
                    timeout=60,
                    imap_user=imap_user,
                    imap_password=imap_password,
                )
                if not code_bind:
                    print(f"\n  [!] 自动轮询超时, 目标邮箱: {icloud_email}")
                    code_bind = input("  [?] 输入6位验证码: ").strip()
                if not code_bind:
                    return {"ok": False, "error": "binding code timeout"}
            log(f"[7] 绑定验证码: {code_bind}")

            # ---- [8] 验证 + workspace + 取 code ----
            r = flow.verify_email_otp(code_bind)
            if r.get("error"):
                log(f"[8] 失败: {r.get('error')}")
                return {"ok": False, "error": f"verify_email_otp: {r.get('error')}"}
            log(f"[8] page: {(r.get('page') or {}).get('type', '?')}")
            continue_url = r.get("continue_url", "")

            if not continue_url:
                dump = flow.get_session_dump()
                workspaces = ((dump.get("client_auth_session") or {}).get("workspaces") or [])
                if workspaces:
                    ws_id = workspaces[0].get("id", "")
                    ws_r = flow.select_workspace(ws_id)
                    continue_url = ws_r.get("continue_url", "")

            code = flow.follow_continue_until_code(continue_url) if continue_url else None
            if not code:
                code = flow.final_oauth(oauth_params)
            if not code:
                return {"ok": False, "error": "no authorization code"}

        log(f"[10] code 获取成功: {code[:30]}...")

        # ---- [11] code → exchange-code → SUB2API 账号 ----
        if sub2api_url and sub2api_email and sub2api_session_id:
            log("[11] SUB2API exchange-code ...")
            import requests as req_lib, time as _time

            resp = req_lib.post(
                f"{sub2api_url}/api/v1/auth/login",
                json={"email": sub2api_email, "password": sub2api_password},
                timeout=30,
            )
            d = resp.json()
            if d.get("code") != 0:
                log(f"[11] SUB2API 登录失败: {d}")
                return {"ok": False, "error": f"SUB2API login failed: {d}"}
            admin_token = d["data"]["access_token"]

            # 用 exchange-code 换 token (带重试)
            exchange_data = None
            for attempt in range(3):
                log(f"[11] exchange-code 尝试 {attempt+1}/3 ...")
                r = req_lib.post(
                    f"{sub2api_url}/api/v1/admin/openai/exchange-code",
                    json={
                        "session_id": sub2api_session_id,
                        "code": code,
                        "state": sub2api_state,
                    },
                    headers={"Authorization": f"Bearer {admin_token}"},
                    timeout=300,
                )
                log(f"[11] response: {r.status_code}")
                if r.status_code == 200:
                    try:
                        exchange_data = r.json()
                    except Exception:
                        exchange_data = r.json()
                    break
                elif r.status_code == 502:
                    log(f"[11] 502, retrying in {attempt+1}s...")
                    _time.sleep(attempt + 1)
                    continue
                else:
                    log(f"[11] exchange-code 失败: {r.status_code} {r.text[:200]}")
                    return {"ok": False, "error": f"exchange-code: {r.status_code}"}

            if not exchange_data:
                return {"ok": False, "error": "exchange-code 502 after 3 retries"}

            # 用 exchange-code 返回的 credentials 创建账号
            creds = exchange_data.get("data", exchange_data)
            email_from_creds = creds.get("email", "") or icloud_email

            body = {
                "name": email_from_creds,
                "platform": "openai",
                "type": "oauth",
                "credentials": {
                    "access_token": creds.get("access_token", ""),
                    "refresh_token": creds.get("refresh_token", ""),
                    "expires_at": creds.get("expires_at", 0),
                    "email": email_from_creds,
                },
                "group_ids": [4],
                "priority": 1,
                "concurrency": 10,
                "auto_pause_on_expired": True,
            }
            r = req_lib.post(
                f"{sub2api_url}/api/v1/admin/accounts",
                json=body,
                headers={"Authorization": f"Bearer {admin_token}"},
                timeout=30,
            )
            d = r.json()
            log(f"[11] 账号创建: code={d.get('code')} id={d.get('data',{}).get('id','?')}")
            return {"ok": True, "code": code, "sub2api_account_id": str(d.get("data", {}).get("id", ""))}

        log("[11] 无 SUB2API 配置, 仅返回 code")
        return {"ok": True, "code": code}

    except Exception as e:
        log(f"异常: {e}")
        return {"ok": False, "error": str(e)}


if __name__ == "__main__":
    print("OpenAI 后半段 — 真实端点版")
    print()
    print("流程: OAuth → sentinel → 手机号 → 密码 → 绑邮箱 → OTP验证 → workspace → code")
    print()
    print("使用: from openai_bind_email import run_second_half")
