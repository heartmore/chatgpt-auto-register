#!/usr/bin/env python3
"""
OpenAI 全链路自动化 — 完整版
前半段: 接码 + 纯协议注册 → session_token
后半段: 绑 iCloud → OAuth 重登录 → 同意 → 回调 → token → SUB2API

用法:
    # 完整链路
    python openai_pipeline.py run \\
        --sms-key KEY --icloud-cookies cookies.json \\
        --sub2api-url URL --sub2api-email E --sub2api-password P

    # 仅后半段（已有 session_token）
    python openai_pipeline.py resume \\
        --session-token TOKEN --email alias@icloud.com \\
        --password pwd --icloud-cookies cookies.json \\
        --sub2api-url URL --sub2api-email E --sub2api-password P
"""

import os
import sys
import re
import json
import time
import secrets
import argparse
from typing import Optional, Dict, Any, Callable

# ============================================================
# 工具
# ============================================================

def rand_password(length: int = 16) -> str:
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%"
    return "".join(secrets.choice(chars) for _ in range(length))


def load_json(path: str) -> Dict:
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


# ============================================================
# 主流水线
# ============================================================

class FullPipeline:
    """OpenAI 全链路: 注册 + 绑邮箱 + OAuth + 上传"""

    def __init__(
        self,
        sms_api_key: str = "",
        sms_provider: str = "smsbower",
        proxy: str = "",
        email_provider: str = "",
        mailmanage_api_key: str = "",
        mailmanage_base_url: str = "",
        mailmanage_keyword: str = "",
        icloud_cookies: Dict = None,
        sub2api_url: str = "",
        sub2api_email: str = "",
        sub2api_password: str = "",
        sub2api_proxy_id: int = 0,
        verbose: bool = True,
    ):
        self.verbose = verbose
        self.proxy = proxy
        self.sms_api_key = sms_api_key
        self.sms_provider = sms_provider
        self.email_provider = email_provider
        self.mailmanage_api_key = mailmanage_api_key
        self.mailmanage_base_url = mailmanage_base_url or "https://mailmanage.lizaliza.top"
        self.mailmanage_category = mailmanage_category
        self.mailmanage_keyword = mailmanage_keyword
        self.icloud_cookies = icloud_cookies or {}
        self.sub2api_url = sub2api_url.rstrip("/") if sub2api_url else ""
        self.sub2api_email = sub2api_email
        self.sub2api_password = sub2api_password
        self.sub2api_proxy_id = sub2api_proxy_id

    def log(self, msg: str):
        print(f"  {msg}")

    # ============================================================
    # 前半段: 手机号注册
    # ============================================================

    def phase1_register(
        self,
        country: str = "151",
        name: str = "A",
        birthdate: str = "2000-01-01",
    ) -> Optional[Dict]:
        """
        前半段: 接码 + 纯协议注册 ChatGPT
        返回: {"session_token": "...", "phone": "...", "password": "..."}
        """
        self.log("=" * 50)
        self.log("前半段: 手机号注册 ChatGPT")
        self.log("=" * 50)

        from phone_sms import PhoneSMS
        from chatgpt_register import register_phone_account

        # 获取号码
        self.log("获取手机号 ...")
        sms = PhoneSMS(self.sms_provider, self.sms_api_key)
        activation = sms.get_number(service="openai", country=country)
        phone = activation.phone
        if not phone.startswith("+"):
            phone = "+" + phone
        self.log(f"手机号: {phone} (id={activation.id})")

        password = rand_password()
        self.log(f"密码: {password}")

        # 注册
        self.log("开始纯协议注册 ...")

        def _wait_sms():
            return sms.wait_for_code(activation.id, timeout=180, verbose=self.verbose)

        result = register_phone_account(
            phone=phone,
            password=password,
            proxy=self.proxy,
            sms_wait_fn=_wait_sms,
            name=name,
            birthdate=birthdate,
            verbose=self.verbose,
        )

        if not result.get("ok"):
            sms.cancel(activation.id)
            self.log(f"注册失败: {result.get('error')}")
            return None

        sms.finish(activation.id)
        self.log(f"注册成功! session_token={bool(result.get('session_token'))}")
        return {
            "session_token": result["session_token"],
            "access_token": result.get("access_token", ""),
            "phone": phone,
            "password": password,
        }

    # ============================================================
    # 中间: 创建 iCloud 别名
    # ============================================================

    def create_icloud_alias(self) -> Optional[str]:
        """获取 iCloud 隐私邮箱"""
        self.log("获取 iCloud 隐私邮箱 ...")
        from icloud_hme import ICloudHME

        try:
            cookies = self.icloud_cookies
            if not cookies:
                from icloud_hme import extract_chrome_cookies
                cookies = extract_chrome_cookies()

            icloud = ICloudHME(cookies, verbose=self.verbose)
            aliases = icloud.list_aliases()
            reusable = next(
                (a for a in aliases if a.get("active") and not a.get("used")), None
            )
            if reusable:
                email = reusable["email"]
                self.log(f"复用 iCloud 别名: {email}")
                return email

            email = icloud.create_alias()
            self.log(f"已创建 iCloud 别名: {email}")
            return email

        except Exception as e:
            self.log(f"iCloud 失败: {e}")
            return None

    def _get_mailmanage_email(self) -> Optional[str]:
        """从 MailManage 获取可用邮箱"""
        self.log(f"MailManage 获取邮箱 (category={self.mailmanage_category}) ...")
        from mailmanage_client import MailManageClient

        try:
            client = MailManageClient(
                api_key=self.mailmanage_api_key,
                base_url=self.mailmanage_base_url,
                verbose=self.verbose,
            )
            email = client.get_available_email(category=self.mailmanage_category)
            if email:
                self.log(f"MailManage 选定: {email}")
                return email
            self.log("MailManage 无可用邮箱")
            return None
        except Exception as e:
            self.log(f"MailManage 失败: {e}")
            return None

    # ============================================================
    # 后半段: 绑邮箱 + OAuth 重登录 + 上传
    # ============================================================

    def phase2_bind_and_upload(
        self,
        phone: str,
        password: str,
        icloud_email: str,
        session_token: str = "",
        oauth_url: str = "",
    ) -> bool:
        """
        后半段 (真实端点):
          ① POST /oauth/authorize
          ② sentinel authorize_continue
          ③ /api/accounts/authorize/continue (手机号)
          ④ sentinel password_verify
          ⑤ /api/accounts/password/verify
          ⑥ /api/accounts/add-email/send (绑iCloud)
          ⑦ iCloud收验证码
          ⑧ /api/accounts/email-otp/validate
          ⑨ /api/accounts/workspace/select
          ⑩ /api/oauth/oauth2/auth → code
          ⑪ code→token + SUB2API
        """
        self.log("=" * 50)
        self.log("后半段: 手机OAuth → 绑邮箱 → OTP验证 → 同意 → code → 上传")
        self.log("=" * 50)

        if oauth_url:
            from openai_bind_email import run_second_half

            result = run_second_half(
                oauth_url=oauth_url,
                phone=phone,
                password=password,
                icloud_email=icloud_email,
                icloud_cookies=self.icloud_cookies,
                sub2api_url=self.sub2api_url,
                sub2api_email=self.sub2api_email,
                sub2api_password=self.sub2api_password,
                sub2api_proxy_id=self.sub2api_proxy_id,
                proxy=self.proxy,
                verbose=self.verbose,
                mailmanage_api_key=self.mailmanage_api_key,
                mailmanage_base_url=self.mailmanage_base_url,
                mailmanage_keyword=self.mailmanage_keyword,
            )

            if result.get("ok"):
                self.log(f"后半段成功! access_token={bool(result.get('access_token'))}")
                if result.get("sub2api_account_id"):
                    self.log(f"  SUB2API id: {result['sub2api_account_id']}")
                return True
            else:
                self.log(f"后半段失败: {result.get('error')}")
                return False

        elif self.sub2api_url:
            # 简化路径: 直接上传 session (无 OAuth)
            self.log("无 OAuth URL，直接上传 session 到 SUB2API ...")
            import requests as req_lib

            try:
                resp = req_lib.post(
                    f"{self.sub2api_url}/api/v1/auth/login",
                    json={"email": self.sub2api_email, "password": self.sub2api_password},
                    timeout=30,
                )
                data = resp.json()
                if data.get("code") != 0:
                    raise RuntimeError(f"登录失败: {data}")
                admin_token = data["data"]["access_token"]

                body = {
                    "content": json.dumps({
                        "session_token": session_token,
                        "email": icloud_email,
                    }),
                    "group_ids": [1],
                    "priority": 1,
                    "auto_pause_on_expired": True,
                    "update_existing": True,
                }
                if self.sub2api_proxy_id:
                    body["proxy_id"] = self.sub2api_proxy_id

                resp = req_lib.post(
                    f"{self.sub2api_url}/api/v1/admin/accounts/import/codex-session",
                    json=body,
                    headers={"Authorization": f"Bearer {admin_token}"},
                    timeout=60,
                )
                data = resp.json()
                if data.get("code") == 0:
                    result = data.get("data", {})
                    self.log(f"上传完成: 新建={result.get('created',0)} 更新={result.get('updated',0)}")
                    return True
                else:
                    self.log(f"上传失败: {data}")
                    return False
            except Exception as e:
                self.log(f"上传异常: {e}")
                return False

        else:
            self.log("未配置 SUB2API，跳过上传")
            self.log(f"  session_token: {session_token[:40]}...")
            self.log(f"  email: {icloud_email}")
            self.log(f"  password: {password}")
            return True

    # ============================================================
    # 生成 OAuth URL (从 SUB2API)
    # ============================================================

    def get_oauth_url(self) -> Optional[str]:
        """从 SUB2API 生成 OAuth 授权链接"""
        if not self.sub2api_url:
            return None

        self.log("从 SUB2API 获取 OAuth URL ...")
        import requests as req_lib

        try:
            resp = req_lib.post(
                f"{self.sub2api_url}/api/v1/auth/login",
                json={"email": self.sub2api_email, "password": self.sub2api_password},
                timeout=30,
            )
            data = resp.json()
            if data.get("code") != 0:
                raise RuntimeError(f"登录失败: {data}")
            token = data["data"]["access_token"]

            body = {"redirect_uri": "http://localhost:1455/auth/callback"}
            if self.sub2api_proxy_id:
                body["proxy_id"] = self.sub2api_proxy_id

            resp = req_lib.post(
                f"{self.sub2api_url}/api/v1/admin/openai/generate-auth-url",
                json=body,
                headers={"Authorization": f"Bearer {token}"},
                timeout=30,
            )
            data = resp.json()
            if data.get("code") != 0:
                raise RuntimeError(f"生成失败: {data}")

            oauth_url = data["data"]["auth_url"]
            self.log(f"OAuth URL 已生成: {oauth_url[:80]}...")
            return oauth_url

        except Exception as e:
            self.log(f"获取 OAuth URL 失败: {e}")
            return None

    # ============================================================
    # 全链路执行
    # ============================================================

    def run_full(
        self,
        country: str = "151",
        name: str = "A",
        birthdate: str = "2000-01-01",
    ) -> Dict:
        print("=" * 50)
        print("OpenAI 全链路自动注册 — 完整版")
        print("=" * 50)

        results = {}

        # ---- Phase 1: 注册 ----
        reg = self.phase1_register(country, name, birthdate)
        if not reg:
            print("\n[失败] 注册阶段失败")
            return {"ok": False, "phase": "register"}

        session_token = reg["session_token"]
        phone = reg["phone"]
        password = reg["password"]
        results.update(reg)

        # ---- iCloud 别名 ----
        email = self.create_icloud_alias()
        results["email"] = email

        # ---- Phase 2: 手机OAuth → 绑邮箱 → 验证 → 同意 → code → 上传 ----
        oauth_url = self.get_oauth_url()
        ok = self.phase2_bind_and_upload(
            phone=phone,
            password=password,
            icloud_email=email or "",
            session_token=session_token,
            oauth_url=oauth_url,
        )

        if ok and self.email_provider == "mailmanage" and email:
            try:
                from mailmanage_client import MailManageClient
                mc = MailManageClient(
                    api_key=self.mailmanage_api_key,
                    base_url=self.mailmanage_base_url,
                    verbose=self.verbose,
                )
                mc.mark_used(email)
            except Exception as e:
                self.log(f"MailManage 标记已用失败: {e}")

        print("=" * 50)
        if ok:
            print("全部流程完成!")
            print(f"  phone: {phone}")
            print(f"  password: {password}")
            print(f"  email: {email}")
            print(f"  session_token: {session_token[:40]}...")
        else:
            print("部分流程失败，检查上方错误信息")

        results["ok"] = ok
        return results


# ============================================================
# 恢复模式（仅后半段）
# ============================================================

def resume_pipeline(
    oauth_url: str,
    phone: str,
    password: str,
    icloud_email: str,
    icloud_cookies: Dict,
    sub2api_url: str,
    sub2api_email: str,
    sub2api_password: str,
    sub2api_proxy_id: int = 0,
    proxy: str = "",
    verbose: bool = True,
    mailmanage_api_key: str = "",
    mailmanage_base_url: str = "",
    mailmanage_keyword: str = "gpt",
) -> bool:
    """从 OAuth URL 执行后半段"""
    from openai_bind_email import run_second_half

    result = run_second_half(
        oauth_url=oauth_url,
        phone=phone,
        password=password,
        icloud_email=icloud_email,
        icloud_cookies=icloud_cookies,
        sub2api_url=sub2api_url,
        sub2api_email=sub2api_email,
        sub2api_password=sub2api_password,
        sub2api_proxy_id=sub2api_proxy_id,
        proxy=proxy,
        verbose=verbose,
        mailmanage_api_key=mailmanage_api_key,
        mailmanage_base_url=mailmanage_base_url,
        mailmanage_keyword=mailmanage_keyword,
    )
    return result.get("ok", False)


# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="OpenAI 全链路自动注册 — 完整版",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    # run
    p = sub.add_parser("run", help="完整链路: 注册 + 绑邮箱 + OAuth + 上传")
    p.add_argument("--sms-provider", default="smsbower")
    p.add_argument("--sms-key", required=True)
    p.add_argument("--country", default="151", help="国家 ID (151=Chile)")
    p.add_argument("--proxy", default="", help="代理 socks5h://127.0.0.1:10808")
    p.add_argument("--icloud-cookies", default="")
    p.add_argument("--sub2api-url", default="")
    p.add_argument("--sub2api-email", default="")
    p.add_argument("--sub2api-password", default="")
    p.add_argument("--sub2api-proxy-id", type=int, default=0)
    p.add_argument("--email-provider", default="", help="邮箱 provider (icloud / mailmanage)")
    p.add_argument("--mailmanage-key", default="", help="MailManage API Key (mak_xxx)")
    p.add_argument("--mailmanage-base-url", default="", help="MailManage 地址")
    p.add_argument("--mailmanage-category", default="free", help="MailManage 分类")
    p.add_argument("--mailmanage-keyword", default="gpt", help="MailManage 关键词")
    p.add_argument("--verbose", "-v", action="store_true")

    # resume
    p2 = sub.add_parser("resume", help="执行后半段 OAuth 流程")
    p2.add_argument("--oauth-url", required=True, help="OAuth 授权 URL (从SUB2API获取)")
    p2.add_argument("--phone", required=True, help="注册手机号 (含国家码)")
    p2.add_argument("--email", required=True, help="iCloud 邮箱别名")
    p2.add_argument("--password", required=True, help="ChatGPT 密码")
    p2.add_argument("--icloud-cookies", required=True, help="iCloud cookies.json")
    p2.add_argument("--proxy", default="")
    p2.add_argument("--sub2api-url", required=True)
    p2.add_argument("--sub2api-email", required=True)
    p2.add_argument("--sub2api-password", required=True)
    p2.add_argument("--sub2api-proxy-id", type=int, default=0)
    p2.add_argument("--verbose", "-v", action="store_true")

    # only-oauth — 测试 OAuth 流程
    p3 = sub.add_parser("test-oauth", help="测试 OAuth 登录流程")
    p3.add_argument("--oauth-url", required=True)
    p3.add_argument("--email", required=True)
    p3.add_argument("--password", required=True)
    p3.add_argument("--session-token", default="")
    p3.add_argument("--proxy", default="")
    p3.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == "run":
        pipeline = FullPipeline(
            sms_api_key=args.sms_key,
            sms_provider=args.sms_provider,
            proxy=args.proxy,
            email_provider=args.email_provider,
            mailmanage_api_key=args.mailmanage_key,
            mailmanage_base_url=args.mailmanage_base_url,
            mailmanage_category=args.mailmanage_category,
            mailmanage_keyword=args.mailmanage_keyword,
            icloud_cookies=load_json(args.icloud_cookies),
            sub2api_url=args.sub2api_url,
            sub2api_email=args.sub2api_email,
            sub2api_password=args.sub2api_password,
            sub2api_proxy_id=args.sub2api_proxy_id,
            verbose=args.verbose,
        )
        pipeline.run_full(country=args.country)

    elif args.command == "resume":
        ok = resume_pipeline(
            oauth_url=args.oauth_url,
            phone=args.phone,
            password=args.password,
            icloud_email=args.email,
            icloud_cookies=load_json(args.icloud_cookies),
            sub2api_url=args.sub2api_url,
            sub2api_email=args.sub2api_email,
            sub2api_password=args.sub2api_password,
            sub2api_proxy_id=args.sub2api_proxy_id,
            proxy=args.proxy,
            verbose=args.verbose,
        )
        print(f"\n结果: {'成功' if ok else '失败'}")

    elif args.command == "test-oauth":
        from openai_bind_email import BindEmailFlow
        flow = BindEmailFlow(
            session_token=args.session_token,
            proxy=args.proxy,
            verbose=args.verbose,
        )
        code = flow.oauth_full_flow(
            oauth_url=args.oauth_url,
            email=args.email,
            password=args.password,
        )
        if code:
            print(f"\n成功! code={code}")
        else:
            print("\n失败: 未获取到 authorization code")


if __name__ == "__main__":
    main()
