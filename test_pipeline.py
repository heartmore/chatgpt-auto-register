#!/usr/bin/env python3
"""
测试脚本: +56978682516 → OAuth → 绑iCloud → code → SUB2API(CHATGPT分组)

不得走 at 偏方，必须走 generate-auth-url → exchange-code 正规路径
"""

import json
import os
import time
import sys
from urllib.parse import urlparse, parse_qs

# ============================================================
# 配置 (来自 FlowPilot settings)
# ============================================================

PHONE = os.environ.get("TEST_PHONE", "+56XXXXXXXXX")
PASSWORD = os.environ.get("TEST_PASSWORD", "your-password")

SUB2API_BASE = os.environ.get("SUB2API_URL", "https://sub2api.example.com")
SUB2API_EMAIL = os.environ.get("SUB2API_EMAIL", "")
SUB2API_PASSWORD = os.environ.get("SUB2API_PASSWORD", "")
SUB2API_GROUP = "CHATGPT"

ICLOUD_HOST = "icloud.com.cn"
REDIRECT_URI = "http://localhost:1455/auth/callback"

# ============================================================
# 工具
# ============================================================

import requests as req_lib

def login_sub2api() -> str:
    """登录 SUB2API，返回 admin_token"""
    resp = req_lib.post(
        f"{SUB2API_BASE}/api/v1/auth/login",
        json={"email": SUB2API_EMAIL, "password": SUB2API_PASSWORD},
        timeout=30,
    )
    data = resp.json()
    if data.get("code") != 0:
        raise RuntimeError(f"SUB2API 登录失败: {data}")
    return data["data"]["access_token"]


def get_oauth_url(admin_token: str) -> dict:
    """从 SUB2API 获取 OAuth URL + session_id + state"""
    resp = req_lib.post(
        f"{SUB2API_BASE}/api/v1/admin/openai/generate-auth-url",
        json={"redirect_uri": REDIRECT_URI},
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=30,
    )
    data = resp.json()
    if data.get("code") != 0:
        raise RuntimeError(f"生成 OAuth URL 失败: {data}")
    result = data["data"]
    return {
        "oauth_url": result["auth_url"],
        "session_id": result["session_id"],
        "state": result.get("state", ""),
    }


def get_icloud_alias(cookies: dict) -> str:
    """从 iCloud 获取/复用隐私邮箱"""
    from icloud_hme import ICloudHME
    icloud = ICloudHME(cookies, host=ICLOUD_HOST, verbose=True)
    aliases = icloud.list_aliases()
    reusable = next((a for a in aliases if a.get("active")), None)
    if reusable:
        print(f"  [iCloud] 复用: {reusable['email']}")
        return reusable["email"]
    alias = icloud.create_alias()
    print(f"  [iCloud] 新建: {alias}")
    return alias


def exchange_code_and_create(admin_token: str, session_id: str, code: str,
                             state: str = "") -> dict:
    """提交 code 到 SUB2API exchange-code → 自动创建账号"""
    body = {"session_id": session_id, "code": code}
    if state:
        body["state"] = state

    resp = req_lib.post(
        f"{SUB2API_BASE}/api/v1/admin/openai/exchange-code",
        json=body,
        headers={"Authorization": f"Bearer {admin_token}"},
        timeout=60,
    )
    data = resp.json()
    if data.get("code") != 0:
        raise RuntimeError(f"exchange-code 失败: {data}")
    return data["data"]


# ============================================================
# 主流程
# ============================================================

def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--bind-code", default="", help="手动 iCloud 绑定验证码（不填则用 IMAP 自动轮询）")
    p.add_argument("--alias", default="", help="指定 iCloud 别名(不创建新的)")
    p.add_argument("--phone", default=PHONE, help=f"手机号 (默认 {PHONE})")
    p.add_argument("--imap-user", default="", help="iCloud login email")
    p.add_argument("--imap-pass", default="", help="iCloud app-specific password")
    args = p.parse_args()

    print("=" * 50)
    print(f"测试: {PHONE} → OAuth → iCloud → SUB2API({SUB2API_GROUP})")
    print("=" * 50)

    # ---- Step 1: iCloud cookies ----
    print("\n[1/5] 加载 iCloud cookies ...")
    cookies_path = r"D:\qingfeng\Documents\逆向包\cookies.json"
    icloud_cookies = json.load(open(cookies_path, encoding="utf-8"))
    print(f"  已加载 {len(icloud_cookies)} 个 cookie")

    # ---- Step 2: SUB2API → 获取 OAuth URL ----
    print("\n[2/5] 从 SUB2API 获取 OAuth URL ...")
    admin_token = login_sub2api()
    oauth_info = get_oauth_url(admin_token)
    oauth_url = oauth_info["oauth_url"]
    session_id = oauth_info["session_id"]
    # state 嵌在 OAuth URL 中，不是 JSON 单独字段
    sub2api_state = parse_qs(urlparse(oauth_url).query).get("state", [""])[0]
    print(f"  OAuth URL: {oauth_url[:100]}...")
    print(f"  Session ID: {session_id}")
    print(f"  State: {sub2api_state}")

    # ---- Step 3: iCloud 别名 ----
    print("\n[3/5] 获取 iCloud 别名 ...")
    icloud_email = ""
    if args.alias:
        icloud_email = args.alias
        print(f"  使用指定别名: {icloud_email}")
    elif icloud_cookies:
        try:
            icloud_email = get_icloud_alias(icloud_cookies)
        except Exception as e:
            print(f"  iCloud 失败: {e}")
            icloud_email = ""
    else:
        print("  无 iCloud cookies，跳过")
        icloud_email = ""

    # ---- Step 4: OAuth 登录流程 ----
    print(f"\n[4/5] OAuth 流程: 手机号 {PHONE} 登录 ...")
    from openai_bind_email import run_second_half

    result = run_second_half(
        oauth_url=oauth_url,
        phone=args.phone,
        password=PASSWORD,
        icloud_email=icloud_email,
        icloud_cookies=icloud_cookies,
        sub2api_url=SUB2API_BASE,
        sub2api_email=SUB2API_EMAIL,
        sub2api_password=SUB2API_PASSWORD,
        sub2api_proxy_id=0,
        verbose=True,
        bind_code=args.bind_code,
        imap_user=args.imap_user,
        imap_password=args.imap_pass,
        sub2api_session_id=session_id,
        sub2api_state=sub2api_state,
    )

    if not result.get("ok"):
        print(f"\n[FAIL] 流程失败: {result.get('error')}")
        sys.exit(1)

    print("\n" + "=" * 50)
    print("全流程完成!")
    print(f"  phone:   {PHONE}")
    print(f"  email:   {icloud_email or '(未绑定)'}")
    print(f"  code:    {result.get('code','')[:30]}...")
    if result.get("sub2api_account_id"):
        print(f"  SUB2API: id={result['sub2api_account_id']}")
    print("=" * 50)


if __name__ == "__main__":
    main()
