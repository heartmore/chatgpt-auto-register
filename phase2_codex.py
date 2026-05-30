"""
Phase 2: Codex OAuth login + bind email + upload to SUB2API.
Depends on the existing tools in D:\qingfeng\Documents\逆向包\
"""

import sys
import json
import time
from typing import Optional, Dict

# Hook into existing Documents folder
_DOCS = r"D:\qingfeng\Documents\逆向包"
if _DOCS not in sys.path:
    sys.path.insert(0, _DOCS)


def codex_login(
    session_token: str,
    phone: str,
    password: str,
    bind_email: str,
    oauth_url: str,
    icloud_cookies: dict = None,
    proxy: str = "",
    sub2api_url: str = "",
    sub2api_email: str = "",
    sub2api_pwd: str = "",
    sub2api_proxy_id: int = 0,
    verbose: bool = True,
) -> Dict:
    """
    Phase 2 full flow:
      1. Phone OAuth login on auth.openai.com
      2. Bind iCloud/HME email
      3. Verify email via iCloud code polling
      4. Email OAuth re-login + MFA
      5. Consent page → capture authorization code
      6. Upload to SUB2API

    Args:
        session_token: from Phase 1 registration
        phone: registered phone number
        password: account password
        bind_email: iCloud/HME email to bind
        oauth_url: pre-generated OAuth URL from SUB2API
        icloud_cookies: iCloud cookies dict for email polling
        proxy: SOCKS5/HTTP proxy
        sub2api_url: SUB2API base URL
        sub2api_email: SUB2API admin email
        sub2api_pwd: SUB2API admin password
        sub2api_proxy_id: SUB2API proxy ID to attach to account

    Returns:
        {"ok": bool, "code": str, "sub2api_account_id": int, "email": str}
    """
    from openai_bind_email import run_second_half

    return run_second_half(
        session_token=session_token,
        phone=phone,
        password=password,
        icloud_email=bind_email,
        oauth_url=oauth_url,
        icloud_cookies=icloud_cookies or {},
        sub2api_url=sub2api_url,
        sub2api_email=sub2api_email,
        sub2api_password=sub2api_pwd,
        sub2api_proxy_id=sub2api_proxy_id,
        proxy=proxy,
        verbose=verbose,
        skip_email_bind=True,
    )


def get_oauth_url(
    sub2api_url: str,
    sub2api_email: str,
    sub2api_pwd: str,
    sub2api_proxy_id: int = 0,
) -> Optional[str]:
    """Generate OAuth URL from SUB2API."""
    import requests as req

    r = req.post(
        f"{sub2api_url}/api/v1/auth/login",
        json={"email": sub2api_email, "password": sub2api_pwd},
        timeout=30,
    )
    data = r.json()
    if data.get("code") != 0:
        raise RuntimeError(f"SUB2API login failed: {data}")

    token = data["data"]["access_token"]
    body = {"redirect_uri": "http://localhost:1455/auth/callback"}
    if sub2api_proxy_id:
        body["proxy_id"] = sub2api_proxy_id

    r = req.post(
        f"{sub2api_url}/api/v1/admin/openai/generate-auth-url",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )
    data = r.json()
    if data.get("code") != 0:
        raise RuntimeError(f"Generate OAuth URL failed: {data}")

    return data["data"]["auth_url"]


def upload_session(
    session_token: str,
    icloud_email: str,
    sub2api_url: str,
    sub2api_email: str,
    sub2api_pwd: str,
    sub2api_proxy_id: int = 0,
    group_ids: list = None,
    access_token: str = "",
) -> dict:
    """Upload session_token + access_token directly to SUB2API.
    Returns: {"ok": bool, "account_id": int, "action": str, "warnings": list}"""
    import requests as req
    if group_ids is None:
        group_ids = [1]

    r = req.post(
        f"{sub2api_url}/api/v1/auth/login",
        json={"email": sub2api_email, "password": sub2api_pwd},
        timeout=30,
    )
    data = r.json()
    if data.get("code") != 0:
        raise RuntimeError(f"SUB2API login failed: {data}")

    admin_token = data["data"]["access_token"]
    body = {
        "content": json.dumps({
            "session_token": session_token,
            "access_token": access_token,
            "email": icloud_email,
        }),
        "group_ids": group_ids,
        "priority": 1,
        "auto_pause_on_expired": True,
        "update_existing": True,
    }
    if sub2api_proxy_id:
        body["proxy_id"] = sub2api_proxy_id

    r = req.post(
        f"{sub2api_url}/api/v1/admin/accounts/import/codex-session",
        json=body,
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=60,
    )
    data = r.json()
    ok = data.get("code") == 0
    result = {"ok": ok, "_raw": data}
    if ok:
        items = data.get("data", {}).get("items", [])
        if items:
            result["account_id"] = items[0].get("account_id") or items[0].get("id")
            result["action"] = items[0].get("action", "unknown")
        else:
            result["account_id"] = data.get("data", {}).get("created") or data.get("data", {}).get("updated")
        result["warnings"] = [str(w) for w in (data.get("data", {}).get("warnings", []) or [])]
        result["_raw"] = data
    return result
