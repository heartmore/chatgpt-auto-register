#!/usr/bin/env python3
"""
OpenAI OAuth 纯协议模块
处理 OAuth 授权码交换、session 管理、邮箱/手机号登录

OpenAI 使用的 OAuth 端点 (Auth0):
  - authorize:  https://auth.openai.com/authorize
  - token:      https://auth.openai.com/oauth/token
  - userinfo:   https://auth.openai.com/userinfo

登录相关端点 (Auth0 Universal Login):
  - identifier: POST /u/login/identifier
  - password:   POST /u/login/password
  - mfa:        POST /u/mfa-otp-challenge
"""

import re
import json
import time
import secrets
import hashlib
import base64
import requests
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlparse, parse_qs, urlencode


# ============================================================
# 常量
# ============================================================

OAUTH_AUTHORIZE_URL = "https://auth.openai.com/authorize"
OAUTH_TOKEN_URL = "https://auth.openai.com/oauth/token"
OAUTH_USERINFO_URL = "https://auth.openai.com/userinfo"
AUTH0_DOMAIN = "https://auth.openai.com"

# 常见的 client_id (从 FlowPilot 的 OAuth URL 中提取)
DEFAULT_CLIENT_ID = "pdlLIX2YH0wG0wLwMfz9eFcXaDh0XaH0"
DEFAULT_REDIRECT_URI = "http://localhost:1455/auth/callback"
DEFAULT_SCOPE = "openid email profile offline_access"
DEFAULT_AUDIENCE = "https://api.openai.com/v1"

# PKCE 相关
CODE_CHALLENGE_METHOD = "S256"


# ============================================================
# 工具函数
# ============================================================

def generate_code_verifier(length: int = 64) -> str:
    """生成 PKCE code_verifier"""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_code_challenge(verifier: str) -> str:
    """从 code_verifier 计算 SHA-256 code_challenge"""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def generate_state() -> str:
    """生成随机的 OAuth state 参数"""
    return secrets.token_hex(32)


def parse_oauth_url(oauth_url: str) -> Dict[str, str]:
    """从 OAuth 授权 URL 中提取参数"""
    parsed = urlparse(oauth_url)
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    return params


def build_oauth_url(
    client_id: str = DEFAULT_CLIENT_ID,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
    scope: str = DEFAULT_SCOPE,
    audience: str = DEFAULT_AUDIENCE,
    state: Optional[str] = None,
    code_challenge: Optional[str] = None,
    login_hint: Optional[str] = None,
    screen_hint: Optional[str] = None,
) -> Tuple[str, str, str]:
    """
    构建 OpenAI OAuth 授权 URL
    返回 (url, state, code_verifier)
    """
    if state is None:
        state = generate_state()

    verifier = generate_code_verifier()
    challenge = code_challenge or generate_code_challenge(verifier)

    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": scope,
        "audience": audience,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": CODE_CHALLENGE_METHOD,
    }
    if login_hint:
        params["login_hint"] = login_hint
    if screen_hint:
        params["screen_hint"] = screen_hint

    url = f"{OAUTH_AUTHORIZE_URL}?{urlencode(params)}"
    return url, state, verifier


# ============================================================
# OAuth Token 交换
# ============================================================

@dataclass
class OAuthTokens:
    access_token: str
    refresh_token: str = ""
    id_token: str = ""
    expires_at: int = 0
    token_type: str = "Bearer"
    email: str = ""
    scope: str = ""

    @classmethod
    def from_exchange(cls, data: Dict) -> "OAuthTokens":
        return cls(
            access_token=data.get("access_token", ""),
            refresh_token=data.get("refresh_token", ""),
            id_token=data.get("id_token", ""),
            expires_at=int(time.time()) + int(data.get("expires_in", 3600)),
            token_type=data.get("token_type", "Bearer"),
            scope=data.get("scope", ""),
        )


class OpenAI_OAuth:
    """OpenAI OAuth 纯协议客户端"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json",
        })

    def _log(self, msg: str):
        if self.verbose:
            print(f"[OAuth] {msg}")

    # ---------- Token 交换 ----------

    def exchange_code(
        self,
        code: str,
        redirect_uri: str = DEFAULT_REDIRECT_URI,
        code_verifier: Optional[str] = None,
        client_id: str = DEFAULT_CLIENT_ID,
    ) -> OAuthTokens:
        """用授权码交换 access_token (纯 HTTP)"""
        self._log("正在交换授权码获取 access_token...")

        payload = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
        }
        if code_verifier:
            payload["code_verifier"] = code_verifier

        resp = self.session.post(
            OAUTH_TOKEN_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )

        if not resp.ok:
            text = resp.text[:300]
            raise RuntimeError(f"Token 交换失败 ({resp.status_code}): {text}")

        data = resp.json()
        tokens = OAuthTokens.from_exchange(data)

        # 解码 id_token 获取 email
        if tokens.id_token:
            try:
                claims = self._decode_jwt(tokens.id_token)
                tokens.email = claims.get("email", "")
            except Exception:
                pass

        self._log(f"Token 获取成功: {tokens.email or '(无email)'}, "
                  f"过期: {tokens.expires_at}")
        return tokens

    def refresh_token(
        self,
        refresh_token: str,
        client_id: str = DEFAULT_CLIENT_ID,
    ) -> OAuthTokens:
        """用 refresh_token 刷新 access_token"""
        self._log("正在刷新 access_token...")

        resp = self.session.post(
            OAUTH_TOKEN_URL,
            json={
                "grant_type": "refresh_token",
                "client_id": client_id,
                "refresh_token": refresh_token,
            },
            headers={"Content-Type": "application/json"},
            timeout=30,
        )

        if not resp.ok:
            raise RuntimeError(f"Token 刷新失败 ({resp.status_code}): {resp.text[:300]}")

        return OAuthTokens.from_exchange(resp.json())

    def get_userinfo(self, access_token: str) -> Dict:
        """获取用户信息"""
        resp = self.session.get(
            OAUTH_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=30,
        )
        if not resp.ok:
            raise RuntimeError(f"获取用户信息失败: {resp.status_code}")
        return resp.json()

    # ---------- Session 检测 ----------

    def check_session(self, access_token: str) -> Dict:
        """检查 session 是否有效"""
        resp = self.session.get(
            "https://chatgpt.com/backend-api/sentinel/chat-requirements",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=30,
        )
        return {
            "valid": resp.ok,
            "status": resp.status_code,
            "data": resp.json() if resp.ok else None,
        }

    # ---------- 内部函数 ----------

    @staticmethod
    def _decode_jwt(token: str) -> Dict:
        """解码 JWT payload (不验证签名)"""
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        payload = parts[1]
        # 补齐 base64 padding
        payload += "=" * (4 - len(payload) % 4)
        try:
            return json.loads(base64.urlsafe_b64decode(payload))
        except Exception:
            return {}

    # ---------- 从 SUB2API 获取 OAuth URL ----------

    @staticmethod
    def get_oauth_url_from_sub2api(
        sub2api_url: str,
        sub2api_email: str,
        sub2api_password: str,
        proxy_id: Optional[int] = None,
    ) -> Tuple[str, str, str]:
        """
        从 SUB2API 获取 OAuth 授权 URL
        返回 (oauth_url, session_id, state)
        """
        # 登录
        resp = requests.post(
            f"{sub2api_url}/api/v1/auth/login",
            json={"email": sub2api_email, "password": sub2api_password},
            timeout=30,
        )
        data = resp.json()
        if data.get("code") != 0:
            raise RuntimeError(f"SUB2API 登录失败: {data}")
        token = data["data"]["access_token"]

        # 生成 OAuth URL
        body = {"redirect_uri": DEFAULT_REDIRECT_URI}
        if proxy_id:
            body["proxy_id"] = proxy_id

        resp = requests.post(
            f"{sub2api_url}/api/v1/admin/openai/generate-auth-url",
            json=body,
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        data = resp.json()
        if data.get("code") != 0:
            raise RuntimeError(f"生成 OAuth URL 失败: {data}")

        result = data["data"]
        oauth_url = result["auth_url"]
        session_id = result["session_id"]
        state = result.get("state", "")

        return oauth_url, session_id, state


# 兼容别名
OpenAIOAuth = OpenAI_OAuth
OAuthTokens = OAuthTokens


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--code", help="OAuth 授权码")
    p.add_argument("--code-verifier", default="")
    p.add_argument("--redirect-uri", default=DEFAULT_REDIRECT_URI)
    p.add_argument("--sub2api-url", help="从 SUB2API 获取 OAuth URL")
    p.add_argument("--sub2api-email", default="")
    p.add_argument("--sub2api-password", default="")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()

    oauth = OpenAI_OAuth(verbose=args.verbose)

    if args.sub2api_url:
        url, sid, st = oauth.get_oauth_url_from_sub2api(
            args.sub2api_url, args.sub2api_email, args.sub2api_password
        )
        print(f"OAuth URL: {url}")
        print(f"Session ID: {sid}")
        print(f"State: {st}")
    elif args.code:
        tokens = oauth.exchange_code(
            args.code,
            redirect_uri=args.redirect_uri,
            code_verifier=args.code_verifier or None,
        )
        print(f"Access Token: {tokens.access_token[:50]}...")
        print(f"Email: {tokens.email}")
        print(f"Expires: {tokens.expires_at}")
    else:
        url, state, verifier = build_oauth_url()
        print(f"OAuth URL: {url}")
        print(f"State: {state}")
        print(f"Code Verifier: {verifier}")
