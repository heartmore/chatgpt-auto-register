#!/usr/bin/env python3
"""
MailManage 邮箱管理平台 API 客户端
https://mailmanage.lizaliza.top

功能:
  - 按分类查询邮箱池 (GET /api/mailboxes)
  - 从指定邮箱获取验证码 (GET /api/mail/<email>)
  - 本地标记已用邮箱，下次自动跳过
"""

import json
import os
import time
from pathlib import Path
from typing import Optional, Dict, List

import requests


DEFAULT_BASE_URL = "https://mailmanage.lizaliza.top"
DEFAULT_USED_FILE = str(Path(__file__).parent / "used_emails.json")


class MailManageClient:
    """MailManage 邮箱管理平台客户端"""

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        used_file: str = DEFAULT_USED_FILE,
        verbose: bool = False,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.used_file = used_file
        self.verbose = verbose
        self._used: set = self._load_used()

    def _log(self, msg: str):
        if self.verbose:
            print(f"  [MailManage] {msg}")

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }

    # ---- 本地已用邮箱管理 ----

    def _load_used(self) -> set:
        """从本地文件加载已用邮箱列表"""
        if os.path.isfile(self.used_file):
            try:
                with open(self.used_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return set(data.get("used", []))
            except Exception:
                return set()
        return set()

    def _save_used(self):
        """保存已用邮箱列表到本地文件"""
        with open(self.used_file, "w", encoding="utf-8") as f:
            json.dump({"used": sorted(self._used)}, f, indent=2, ensure_ascii=False)
        self._log(f"已用标记已保存 ({len(self._used)} 个)")

    def mark_used(self, email: str):
        """标记邮箱为已使用，下次获取时跳过"""
        email = email.strip().lower()
        if email and email not in self._used:
            self._used.add(email)
            self._save_used()
            self._log(f"标记已用: {email}")

    def skip_used(self, emails: List[str]) -> List[str]:
        """过滤掉已用过的邮箱"""
        filtered = [e for e in emails if e.strip().lower() not in self._used]
        skipped = len(emails) - len(filtered)
        if skipped:
            self._log(f"跳过 {skipped} 个已用邮箱")
        return filtered

    @property
    def used_count(self) -> int:
        return len(self._used)

    # ---- API 调用 ----

    def list_mailboxes(
        self,
        category: str = "",
        status: str = "",
    ) -> List[Dict]:
        """
        查询邮箱列表
        category: free / 套餐 等
        status: free / invalid / used 等
        """
        params = []
        if category:
            params.append(f"category={category}")
        if status:
            params.append(f"status={status}")
        query = "&".join(params)
        url = f"{self.base_url}/api/mailboxes"
        if query:
            url += f"?{query}"

        self._log(f"查询邮箱列表: category={category or 'all'} status={status or 'all'}")
        resp = requests.get(url, headers=self._headers(), timeout=30)
        data = resp.json()
        if not data.get("ok"):
            raise RuntimeError(f"查询邮箱列表失败: {data}")
        mailboxes = data.get("mailboxes", [])
        self._log(f"获取到 {len(mailboxes)} 个邮箱")
        return mailboxes

    def get_available_email(
        self,
        category: str = "free",
        status: str = "",
    ) -> Optional[str]:
        """
        获取一个可用邮箱（自动跳过已用过的）
        返回邮箱地址，无可用时返回 None
        """
        mailboxes = self.list_mailboxes(category=category, status=status)
        emails = [(mb["email"].strip(), mb["email"].strip().lower()) for mb in mailboxes if mb.get("email")]

        # 用原始大小写展示，用小写做已用比对
        available = [(orig, lower) for orig, lower in emails if lower not in self._used]
        if not available:
            self._log(f"无可用邮箱 (已用 {self.used_count} 个，共 {len(emails)} 个)")
            return None

        email = available[0][0]
        self._log(f"选定邮箱: {email}")
        return email

    def get_code(
        self,
        email: str,
        keyword: str = "gpt",
        limit: int = 10,
        timeout: int = 60,
        interval: int = 5,
    ) -> Optional[Dict]:
        """
        轮询获取验证码
        返回: {"code": "123456", "subject": "...", ...} 或 None
        """
        params = [f"email={email}"]
        if keyword:
            params.append(f"keyword={keyword}")
        if limit:
            params.append(f"limit={limit}")
        url = f"{self.base_url}/api/mail/code?{'&'.join(params)}"

        self._log(f"轮询 {email} 验证码 (keyword={keyword or '无'}, timeout={timeout}s)...")
        start = time.time()
        while time.time() - start < timeout:
            try:
                resp = requests.get(url, headers=self._headers(), timeout=30)
                data = resp.json()
                if data.get("ok") and data.get("found"):
                    code = data.get("code", "")
                    if code:
                        self._log(f"获取到验证码: {code}")
                        return {
                            "code": code,
                            "email": data.get("email", email),
                            "subject": (data.get("message") or {}).get("subject", ""),
                            "from_addr": (data.get("message") or {}).get("from_addr", ""),
                        }
                self._log(f"未找到验证码, {interval}s 后重试...")
            except Exception as e:
                self._log(f"请求异常: {e}")
            time.sleep(interval)

        self._log(f"获取验证码超时 ({timeout}s)")
        return None


# ============================================================
# CLI 测试
# ============================================================

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="MailManage 邮箱管理工具")
    p.add_argument("--api-key", required=True, help="API Key (mak_xxx)")
    p.add_argument("--base-url", default=DEFAULT_BASE_URL, help="API 地址")
    p.add_argument("--command", default="list", choices=["list", "get", "clean"])
    p.add_argument("--category", default="free", help="邮箱分类 (free/套餐)")
    p.add_argument("--email", default="", help="指定邮箱")
    p.add_argument("--keyword", default="gpt", help="验证码检索关键词")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    client = MailManageClient(args.api_key, args.base_url, verbose=args.verbose)

    if args.command == "list":
        print(f"\n已用邮箱数: {client.used_count}")
        print(f"\n邮箱列表 ({args.category}):\n")
        mailboxes = client.list_mailboxes(category=args.category)
        for mb in mailboxes:
            email = mb.get("email", "?")
            used = " [已用]" if email.lower() in client._used else ""
            print(f"  {email}  tag={mb.get('tag','')}  msgs={mb.get('message_count','?')}{used}")

        available = client.get_available_email(category=args.category)
        if available:
            print(f"\n推荐下一个: {available}")

    elif args.command == "get":
        email = args.email
        if not email:
            email = client.get_available_email(category=args.category)
            if not email:
                print("无可用邮箱")
                exit(1)
        print(f"轮询 {email} 验证码...")
        result = client.get_code(email, keyword=args.keyword, timeout=120)
        if result:
            print(f"\n验证码: {result['code']}")
            print(f"发件人: {result['from_addr']}")
            print(f"主题:   {result['subject']}")
            client.mark_used(email)
        else:
            print("超时未获取到验证码")

    elif args.command == "clean":
        import shutil
        if os.path.isfile(DEFAULT_USED_FILE):
            shutil.copy(DEFAULT_USED_FILE, DEFAULT_USED_FILE + ".bak")
            os.remove(DEFAULT_USED_FILE)
            print(f"已清除 {DEFAULT_USED_FILE} (备份: .bak)")
        else:
            print("无已用记录")
