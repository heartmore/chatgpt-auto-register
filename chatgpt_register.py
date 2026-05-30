"""
ChatGPT phone registration protocol engine.
Uses curl_cffi for TLS fingerprint to bypass Cloudflare,
and Sentinel PoW to bypass JS anti-bot challenges.

Based on reverse engineering via Anything Analyzer and open-reg-auto.
"""

import json
import uuid
from typing import Any
from urllib.parse import urlencode

import urllib3
from curl_cffi import requests as curl_requests

from sentinel import Sentinel

urllib3.disable_warnings()

CHATGPT = "https://chatgpt.com"
AUTH = "https://auth.openai.com"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)

# Headers for JSON API calls
COMMON_HEADERS = {
    "accept": "application/json",
    "accept-language": "en-US,en;q=0.9",
    "content-type": "application/json",
    "origin": AUTH,
    "user-agent": UA,
    "sec-ch-ua": '"Google Chrome";v="145"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
}

# Headers for page navigation
NAVIGATE_HEADERS = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "accept-language": "en-US,en;q=0.9",
    "user-agent": UA,
    "sec-ch-ua": '"Google Chrome";v="145"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "none",
    "upgrade-insecure-requests": "1",
}


class ChatGPTRegister:
    """ChatGPT phone registration protocol engine."""

    def __init__(self, proxy: str = "", verbose: bool = True):
        self.verbose = verbose
        self.proxy = proxy
        if proxy:
            import requests as req
            self.session = req.Session()
            self.session.proxies = {"http": proxy, "https": proxy}
            self.session.verify = False
        else:
            self.session = curl_requests.Session(impersonate="chrome", verify=False)

        self.device_id = str(uuid.uuid4())
        self.sentinel = Sentinel(self.device_id)
        self._sentinel_cache: dict[str, dict] = {}

    def _sentinel(self, flow: str) -> dict:
        if flow not in self._sentinel_cache:
            try:
                self._sentinel_cache[flow] = self.sentinel.get(self.session, flow)
            except Exception:
                self._sentinel_cache[flow] = {"token": "", "so_token": ""}
        return self._sentinel_cache[flow]

    def _add_sentinel_headers(self, headers: dict, flow: str):
        """给 headers 添加 Sentinel-Token 和 Sentinel-SO-Token"""
        st = self._sentinel(flow)
        token = st.get("token", "")
        so_token = st.get("so_token", "")
        if token:
            headers["OpenAI-Sentinel-Token"] = token
        if so_token:
            headers["OpenAI-Sentinel-SO-Token"] = so_token

    def _log(self, step: int, msg: str):
        if self.verbose:
            print(f"  [{step:02d}] {msg}")

    # ---- Step 1: 访问 chatgpt.com ----
    def visit(self):
        self._log(1, "访问 chatgpt.com ...")
        self.session.get(
            f"{CHATGPT}/auth/login",
            headers=NAVIGATE_HEADERS,
            allow_redirects=True,
            timeout=30,
        )

    # ---- Step 2: 获取 CSRF token ----
    def get_csrf(self) -> str:
        self._log(2, "GET /api/auth/csrf ...")
        r = self.session.get(
            f"{CHATGPT}/api/auth/csrf",
            headers=COMMON_HEADERS,
            timeout=30,
        )
        csrf = r.json().get("csrfToken")
        if not csrf:
            raise RuntimeError("CSRF token 获取失败 (可能被 Cloudflare 拦截)")
        return csrf

    # ---- Step 3: 发起手机登录 ----
    def signin(self, phone: str, csrf: str) -> str:
        self._log(3, "POST /api/auth/signin/openai ...")
        encoded = phone.replace("+", "%2B")
        params = {
            "prompt": "login",
            "screen_hint": "login_or_signup",
            "login_hint": encoded,
            "ext-oai-did": self.device_id,
            "auth_session_logging_id": str(uuid.uuid4()),
        }
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        r = self.session.post(
            f"{CHATGPT}/api/auth/signin/openai?{qs}",
            data={"callbackUrl": "/", "csrfToken": csrf, "json": "true"},
            headers={
                **COMMON_HEADERS,
                "content-type": "application/x-www-form-urlencoded",
                "origin": CHATGPT,
                "referer": f"{CHATGPT}/auth/login",
            },
            allow_redirects=False,
            timeout=30,
        )
        return r.json().get("url", "")

    # ---- Step 4: 跟随 OAuth 跳转到 auth.openai.com ----
    def jump_to_auth(self, redirect_url: str) -> str:
        self._log(4, "跳转 auth.openai.com ...")
        r = self.session.get(
            redirect_url,
            headers={**NAVIGATE_HEADERS, "referer": CHATGPT, "sec-fetch-site": "cross-site"},
            allow_redirects=False,
            timeout=30,
        )
        location = r.headers.get("Location", "")
        if location:
            self.session.get(
                location,
                headers={**NAVIGATE_HEADERS, "referer": AUTH, "sec-fetch-site": "same-origin"},
                allow_redirects=True,
                timeout=30,
            )
        return location

    # ---- Step 5: 手机号 + 密码注册 ----
    def register_user(self, phone: str, password: str) -> dict:
        self._log(5, "POST /api/accounts/user/register ...")
        headers = {
            **COMMON_HEADERS,
            "referer": f"{AUTH}/create-account/password",
            "oai-device-id": self.device_id,
        }
        try:
            self._add_sentinel_headers(headers, "username_password_create")
        except Exception:
            pass

        r = self.session.post(
            f"{AUTH}/api/accounts/user/register",
            json={"username": phone, "password": password},
            headers=headers,
            timeout=30,
        )
        data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        data["_status"] = r.status_code
        return data

    # ---- Step 6: 发送手机验证码 ----
    def send_otp(self, continue_url: str):
        self._log(6, "GET /api/accounts/phone-otp/send ...")
        self.session.get(
            continue_url,
            headers={**NAVIGATE_HEADERS, "referer": f"{AUTH}/create-account/password"},
            allow_redirects=True,
            timeout=30,
        )

    # ---- Step 7: 验证 OTP 验证码 ----
    def validate_otp(self, code: str) -> dict:
        self._log(7, "POST /api/accounts/phone-otp/validate ...")
        headers = {
            **COMMON_HEADERS,
            "referer": f"{AUTH}/contact-verification",
            "oai-device-id": self.device_id,
        }
        try:
            self._add_sentinel_headers(headers, "authorize_continue")
        except Exception:
            pass
        r = self.session.post(
            f"{AUTH}/api/accounts/phone-otp/validate",
            json={"code": code},
            headers=headers,
            timeout=30,
        )
        data = r.json() if r.ok else {}
        data["_status"] = r.status_code
        return data

    # ---- Step 8: 创建账户 (用户名+生日) ----
    def create_account(self, name: str, birthdate: str) -> dict:
        self._log(8, "POST /api/accounts/create_account ...")
        headers = {
            **COMMON_HEADERS,
            "referer": f"{AUTH}/about-you",
            "oai-device-id": self.device_id,
        }
        try:
            self._add_sentinel_headers(headers, "oauth_create_account")
        except Exception:
            pass
        r = self.session.post(
            f"{AUTH}/api/accounts/create_account",
            json={"name": name, "birthdate": birthdate},
            headers=headers,
            allow_redirects=False,
            timeout=30,
        )
        data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        data["_status"] = r.status_code
        data["_body"] = r.text[:500] if r.text else ""
        return data

    # ---- 访问 about-you 页面建立会话 ----
    def visit_about_you(self, continue_url: str):
        if self.verbose:
            print("  [^^] 访问 about-you 页面 ...")
        url = continue_url if continue_url.startswith("http") else f"{AUTH}{continue_url}"
        self.session.get(
            url,
            headers={**NAVIGATE_HEADERS, "referer": f"{AUTH}/contact-verification", "sec-fetch-site": "same-origin"},
            allow_redirects=True,
            timeout=30,
        )

    # ---- Step 9: OAuth 回调获取 session token ----
    def oauth_callback(self, callback_url: str) -> str:
        self._log(9, "OAuth 回调 ...")
        self.session.get(
            callback_url,
            headers={**NAVIGATE_HEADERS, "referer": AUTH, "sec-fetch-site": "cross-site"},
            allow_redirects=True,
            timeout=30,
        )
        return self.session.cookies.get("__Secure-next-auth.session-token", "")

    # ---- 获取 access token ----
    def get_access_token(self) -> str:
        r = self.session.get(
            f"{CHATGPT}/api/auth/session",
            headers=COMMON_HEADERS,
            timeout=30,
        )
        try:
            return r.json().get("accessToken", "")
        except Exception:
            return ""


def register_phone_account(
    phone: str,
    password: str,
    proxy: str = "",
    sms_wait_fn=None,
    name: str = "A",
    birthdate: str = "2000-01-01",
    verbose: bool = True,
    create_account_retries: int = 1,
) -> dict:
    """One-shot phone registration: gets number -> session_token + access_token."""
    import json
    reg = ChatGPTRegister(proxy=proxy, verbose=verbose)
    try:
        reg.visit()
        csrf = reg.get_csrf()
        redirect = reg.signin(phone, csrf)
        reg.jump_to_auth(redirect)
        result = reg.register_user(phone, password)
        continue_url = result.get("continue_url", "")
        if not continue_url:
            return {"ok": False, "phone": phone, "error": f"注册失败(status={result.get('_status')})"}
        reg.send_otp(continue_url)
        if not sms_wait_fn:
            return {"ok": False, "phone": phone, "error": "no_sms_callback"}
        code = sms_wait_fn()
        if not code:
            return {"ok": False, "phone": phone, "error": "验证码超时"}
        result = reg.validate_otp(code)
        continue_url = result.get("continue_url", "")
        if not continue_url:
            return {"ok": False, "phone": phone, "error": f"验证码校验失败(status={result.get('_status')})"}
        reg.visit_about_you(continue_url)
        result = reg.create_account(name, birthdate)
        callback_url = result.get("continue_url", "")
        if not callback_url:
            detail = result.get("_body", "")
            detail_short = detail[:200] if detail else f"status={result.get('_status')}"
            return {"ok": False, "phone": phone, "name": name, "birthdate": birthdate,
                    "error": f"创建账户失败: {detail_short}"}
        session_token = reg.oauth_callback(callback_url)
        access_token = reg.get_access_token()
        return {"ok": True, "phone": phone, "password": password,
                "session_token": session_token, "access_token": access_token}
    except Exception as e:
        return {"ok": False, "phone": phone, "error": str(e)}
