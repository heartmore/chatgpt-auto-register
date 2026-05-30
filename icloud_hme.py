#!/usr/bin/env python3
"""
iCloud Hide My Email — 纯协议实现
基于 FlowPilot reverse engineering，不依赖浏览器运行。

用法:
    # 从 Chrome 自动提取 cookie
    python icloud_hme.py list

    # 使用手动提供的 cookies.json
    python icloud_hme.py list --cookies cookies.json

    # 生成新别名
    python icloud_hme.py generate

    # 删除指定别名
    python icloud_hme.py delete --email xxx@icloud.com

    # 导出 Chrome cookies 到文件（方便后续复用）
    python icloud_hme.py export-cookies --output cookies.json

依赖: pip install requests pycryptodome pywin32
"""

import sys
import os
import json
import re
import time
import sqlite3
import argparse
import hashlib
import base64
from datetime import datetime
from typing import Optional, Dict, List, Any, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

# ============================================================
# 常量（来自 FlowPilot background.js）
# ============================================================

SETUP_URLS = [
    "https://setup.icloud.com/setup/ws/1",
    "https://setup.icloud.com.cn/setup/ws/1",
]

LOGIN_URLS = [
    "https://www.icloud.com/",
    "https://www.icloud.com.cn/",
]

CLIENT_BUILD_NUMBER = "2206Hotfix11"
REQUEST_TIMEOUT = 15
MAX_RETRIES = 3
RETRY_DELAYS = [1, 2.5, 5]

# iCloud 鉴权所需的 cookie 域
ICLOUD_COOKIE_DOMAINS = [
    ".icloud.com",
    ".icloud.com.cn",
    "icloud.com",
    "icloud.com.cn",
    "setup.icloud.com",
    "setup.icloud.com.cn",
    "www.icloud.com",
    "www.icloud.com.cn",
]


# ============================================================
# Cookie 提取
# ============================================================

def _get_chrome_cookie_path() -> Optional[str]:
    """查找 Chrome 的 Cookie 数据库路径"""
    local_appdata = os.environ.get("LOCALAPPDATA", "")
    candidates = [
        os.path.join(local_appdata, "Google", "Chrome", "User Data", "Default", "Network", "Cookies"),
        os.path.join(local_appdata, "Google", "Chrome", "User Data", "Default", "Cookies"),
    ]
    if not local_appdata:
        return None
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None


def _get_chrome_key() -> Optional[bytes]:
    """从 Chrome Local State 获取加密密钥 (Windows DPAPI)"""
    local_appdata = os.environ.get("LOCALAPPDATA", "")
    state_path = os.path.join(local_appdata, "Google", "Chrome", "User Data", "Local State")
    if not os.path.isfile(state_path):
        return None

    with open(state_path, "r", encoding="utf-8") as f:
        state = json.load(f)

    encrypted_key = base64.b64decode(
        state.get("os_crypt", {}).get("encrypted_key", "")
    )
    if not encrypted_key or len(encrypted_key) < 6:
        return None

    # 去掉 "DPAPI" 前缀 (5 bytes)
    encrypted_key = encrypted_key[5:]

    try:
        import win32crypt
        return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    except ImportError:
        pass

    # 回退：使用 ctypes 调 crypt32.dll
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    crypt32 = ctypes.windll.crypt32
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB), ctypes.c_wchar_p,
        ctypes.POINTER(DATA_BLOB), ctypes.c_void_p,
        ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL

    blob_in = DATA_BLOB(len(encrypted_key), ctypes.c_char_p(encrypted_key))
    blob_out = DATA_BLOB()
    if crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    ):
        result = ctypes.string_at(blob_out.pbData, blob_out.cbData)
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
        return result
    return None


def extract_chrome_cookies() -> Dict[str, str]:
    """从 Chrome 提取 iCloud 相关 cookie，返回 {name: value} 字典"""
    cookie_path = _get_chrome_cookie_path()
    if not cookie_path:
        raise RuntimeError("找不到 Chrome Cookie 数据库，请先用 Chrome 登录 icloud.com")

    key = _get_chrome_key()
    if not key:
        raise RuntimeError("无法获取 Chrome 加密密钥")
    from Crypto.Cipher import AES

    # 连接数据库
    conn = None
    try:
        # 直接连接 (Chrome WAL 模式, 只读)
        conn = sqlite3.connect(f"file:{cookie_path}?mode=ro", uri=True)
    except Exception as e:
        raise RuntimeError(f"无法读取 Chrome Cookie 数据库 (请关闭Chrome后重试): {e}")

    try:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        placeholders = ",".join("?" * len(ICLOUD_COOKIE_DOMAINS))
        cursor.execute(
            f"SELECT name, encrypted_value, host_key FROM cookies WHERE host_key IN ({placeholders})",
            ICLOUD_COOKIE_DOMAINS,
        )
        rows = cursor.fetchall()
    finally:
        if conn:
            conn.close()

    cookies = {}
    for row in rows:
        name = row["name"]
        encrypted = row["encrypted_value"]
        if not encrypted:
            continue

        value = _decrypt_chrome_cookie(encrypted, key)
        if value:
            cookies[name] = value

    return cookies


def _decrypt_chrome_cookie(encrypted_value: bytes, key: bytes) -> Optional[str]:
    """解密单个 Chrome cookie (AES-256-GCM)"""
    from Crypto.Cipher import AES

    # Chrome 80+: v10 (prefix) + 12-byte nonce + ciphertext + 16-byte tag
    if len(encrypted_value) < 3:
        return None
    prefix = encrypted_value[:3]
    if prefix == b"v10" or prefix == b"v11":
        nonce = encrypted_value[3:15]
        ciphertext = encrypted_value[15:-16]
        tag = encrypted_value[-16:]
        if len(ciphertext) < 1:
            return None
        try:
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plain = cipher.decrypt_and_verify(ciphertext, tag)
            return plain.decode("utf-8", errors="replace")
        except Exception:
            return None

    # 旧版 Chrome: 直接用 DPAPI
    if prefix == b"\x01\x00\x00\x00":
        try:
            import win32crypt
            decrypted = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1]
            return decrypted.decode("utf-8", errors="replace")
        except Exception:
            pass

    return None


# ============================================================
# iCloud Hide My Email API 客户端
# ============================================================

class ICloudHME:
    """iCloud Hide My Email 纯协议客户端"""

    def __init__(
        self,
        cookies: Dict[str, str],
        host: str = "icloud.com",
        verbose: bool = False,
    ):
        self.cookies = cookies
        self.host = self._normalize_host(host)
        self.verbose = verbose
        self.session = requests.Session()
        self.session.cookies.update(cookies)
        self._setup_url: Optional[str] = None
        self._service_url: Optional[str] = None
        self._preferred_host: Optional[str] = None

    @staticmethod
    def _normalize_host(host: str) -> str:
        h = host.strip().lower()
        try:
            h = urlparse(h if "://" in h else f"https://{h}").hostname or h
        except Exception:
            pass
        if h.endswith(".icloud.com.cn") or h == "icloud.com.cn":
            return "icloud.com.cn"
        return "icloud.com"

    @property
    def setup_url(self) -> str:
        if not self._setup_url:
            self._setup_url = (
                "https://setup.icloud.com.cn/setup/ws/1"
                if self.host == "icloud.com.cn"
                else "https://setup.icloud.com/setup/ws/1"
            )
        return self._setup_url

    @property
    def origin(self) -> str:
        return f"https://www.{self.host}"

    def _log(self, msg: str):
        if self.verbose:
            print(f"[iCloud] {msg}")

    def _build_url(self, url: str) -> str:
        """追加 clientBuildNumber / clientMasteringNumber 参数"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params["clientBuildNumber"] = [CLIENT_BUILD_NUMBER]
        params["clientMasteringNumber"] = [CLIENT_BUILD_NUMBER]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _request(
        self,
        method: str,
        url: str,
        json_data: Any = None,
        content_type: Optional[str] = None,
        timeout: int = REQUEST_TIMEOUT,
        max_attempts: int = MAX_RETRIES,
    ) -> Any:
        """发送带重试的 HTTP 请求"""
        full_url = self._build_url(url)
        headers = {
            "Origin": self.origin,
            "Referer": self.origin + "/",
            "Accept": "application/json, text/plain, */*",
        }
        if content_type:
            headers["Content-Type"] = content_type
        elif json_data is not None:
            # maildomainws 用 text/plain
            parsed = urlparse(url)
            if "maildomainws" in parsed.hostname:
                headers["Content-Type"] = "text/plain;charset=UTF-8"
            else:
                headers["Content-Type"] = "application/json"
        else:
            headers["Content-Type"] = "application/json"

        body = None
        if json_data is not None:
            body = json.dumps(json_data, ensure_ascii=False)

        last_error = None
        for attempt in range(1, max_attempts + 1):
            try:
                resp = self.session.request(
                    method=method,
                    url=full_url,
                    headers=headers,
                    data=body,
                    timeout=timeout,
                )

                if not resp.ok:
                    text = resp.text[:300]
                    last_error = RuntimeError(
                        f"{method} {url} → HTTP {resp.status_code}: {text}"
                    )
                    if resp.status_code in (401, 403):
                        raise last_error
                    if attempt < max_attempts:
                        delay = RETRY_DELAYS[min(attempt - 1, len(RETRY_DELAYS) - 1)]
                        self._log(f"重试 {attempt}/{max_attempts}（{delay}s 后）...")
                        import time
                        time.sleep(delay)
                        continue
                    raise last_error

                text = resp.text
                if not text:
                    return {}
                return resp.json()

            except requests.exceptions.Timeout:
                last_error = RuntimeError(f"{method} {url} → 超时 ({timeout}s)")
                if attempt < max_attempts:
                    delay = RETRY_DELAYS[min(attempt - 1, len(RETRY_DELAYS) - 1)]
                    self._log(f"超时重试 {attempt}/{max_attempts}（{delay}s 后）...")
                    import time
                    time.sleep(delay)
                    continue
                raise last_error

            except requests.exceptions.ConnectionError as e:
                last_error = RuntimeError(f"{method} {url} → 连接失败: {e}")
                if attempt < max_attempts:
                    delay = RETRY_DELAYS[min(attempt - 1, len(RETRY_DELAYS) - 1)]
                    self._log(f"连接失败重试 {attempt}/{max_attempts}（{delay}s 后）...")
                    import time
                    time.sleep(delay)
                    continue
                raise last_error

        raise last_error or RuntimeError("未知错误")

    # ---------- 会话 ----------

    def validate_session(self) -> Dict:
        """校验 iCloud 会话，返回 webservices 信息"""
        self._log("正在校验 iCloud 会话...")
        data = self._request("POST", f"{self.setup_url}/validate", timeout=20)
        premium = data.get("webservices", {}).get("premiummailsettings", {})
        if not premium.get("url"):
            raise RuntimeError(
                "iCloud 会话校验失败：未找到 Hide My Email 服务。"
                "请确认已开通 iCloud+ 订阅并在浏览器登录了 icloud.com。"
            )
        self._service_url = premium["url"].rstrip("/")
        self._log(f"会话有效 ({self.host})，Premium Mail: {self._service_url}")
        return data

    def _resolve_service(self):
        """确保已校验会话并获取服务 URL"""
        if not self._service_url:
            # 尝试两个域名
            errors = []
            for host in [self.host] + (
                ["icloud.com.cn"] if self.host == "icloud.com" else ["icloud.com"]
            ):
                backup = self.host
                self.host = host
                self._setup_url = None
                try:
                    return self.validate_session()
                except Exception as e:
                    errors.append(f"{host}: {e}")
                    self.host = backup
                    self._setup_url = None
            raise RuntimeError("; ".join(errors))

    # ---------- 别名操作 ----------

    def list_aliases(self) -> List[Dict]:
        """列出所有 Hide My Email 别名"""
        self._resolve_service()
        self._log("正在获取别名列表...")
        response = self._request("GET", f"{self._service_url}/v2/hme/list")
        aliases = self._parse_alias_list(response)
        self._log(f"共 {len(aliases)} 个别名")
        return aliases

    def generate(self) -> str:
        """生成新的候选别名（未保留）"""
        self._resolve_service()
        self._log("正在生成候选别名...")
        response = self._request(
            "POST",
            f"{self._service_url}/v1/hme/generate",
            max_attempts=2,
        )
        if not response.get("success"):
            err = response.get("error", {})
            raise RuntimeError(f"生成失败: {err.get('errorMessage', 'unknown')}")
        hme = response.get("result", {}).get("hme", "")
        if isinstance(hme, dict):
            hme = hme.get("hme") or hme.get("email") or ""
        self._log(f"候选别名: {hme}")
        return hme

    def reserve(self, hme: str, label: Optional[str] = None) -> str:
        """保留/确认一个已生成的候选别名"""
        self._resolve_service()
        if not label:
            now = datetime.now()
            label = f"MultiPage {now.strftime('%Y-%m-%d')}"
        self._log(f"正在保留别名 {hme}...")
        data = {"hme": hme, "label": label, "note": "Generated through FlowPilot"}
        response = self._request(
            "POST",
            f"{self._service_url}/v1/hme/reserve",
            json_data=data,
            max_attempts=2,
        )
        if not response.get("success"):
            err = response.get("error", {})
            raise RuntimeError(f"保留失败: {err.get('errorMessage', 'unknown')}")
        result = response.get("result", {}).get("hme", {})
        alias = result.get("hme", hme) if isinstance(result, dict) else hme
        self._log(f"已保留: {alias}")
        return alias

    def create_alias(self, label: Optional[str] = None, max_retries: int = 5) -> str:
        """生成 + 保留，一步创建新别名。reserve 失败会刷新节点重试"""
        for attempt in range(max_retries):
            if attempt > 0:
                # 刷新服务节点重新获取
                self._service_url = None
                self._setup_url = None
            hme = self.generate()
            try:
                return self.reserve(hme, label)
            except Exception as e:
                self._log(f"reserve 失败 (attempt {attempt+1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    continue
        raise RuntimeError(f"reserve 重试 {max_retries} 次均失败")

    def deactivate(self, anonymous_id: str) -> bool:
        """停用别名"""
        self._resolve_service()
        self._log(f"正在停用 {anonymous_id}...")
        response = self._request(
            "POST",
            f"{self._service_url}/v1/hme/deactivate",
            json_data={"anonymousId": anonymous_id},
            max_attempts=2,
        )
        ok = response.get("success", False)
        self._log("已停用" if ok else f"停用失败: {response.get('error', {})}")
        return ok

    def delete(self, anonymous_id: str) -> bool:
        """删除别名（失败时会尝试先停用再删除）"""
        self._resolve_service()
        self._log(f"正在删除 {anonymous_id}...")
        try:
            response = self._request(
                "POST",
                f"{self._service_url}/v1/hme/delete",
                json_data={"anonymousId": anonymous_id},
                max_attempts=2,
            )
            if response.get("success") is False:
                raise RuntimeError(response.get("error", {}).get("errorMessage", "delete failed"))
        except Exception as e:
            self._log(f"直接删除失败: {e}，尝试先停用再删除...")
            self.deactivate(anonymous_id)
            response = self._request(
                "POST",
                f"{self._service_url}/v1/hme/delete",
                json_data={"anonymousId": anonymous_id},
                max_attempts=2,
            )
            if response.get("success") is False:
                raise RuntimeError(response.get("error", {}).get("errorMessage", "delete failed"))
        self._log("已删除")
        return True

    # ---------- 解析 ----------

    @staticmethod
    def _parse_alias_list(response: Any) -> List[Dict]:
        """从 API 响应中解析别名列表"""
        aliases_raw = None

        # 优先: result.hmeEmails (新版 icloud API)
        if isinstance(response, dict):
            result = response.get("result", {})
            if isinstance(result, dict):
                hme = result.get("hmeEmails")
                if isinstance(hme, list):
                    aliases_raw = hme

        # 回退: 深度遍历找第一个 dict 元素组成的数组
        if not aliases_raw:
            def _find_dict_array(d, depth=0):
                if depth > 4 or d is None:
                    return None
                if isinstance(d, list) and len(d) > 0 and isinstance(d[0], dict):
                    return d
                if isinstance(d, dict):
                    for v in d.values():
                        r = _find_dict_array(v, depth + 1)
                        if r:
                            return r
                return None
            aliases_raw = _find_dict_array(response)

        if not aliases_raw:
            return []

        aliases = []
        for item in aliases_raw:
            if not isinstance(item, dict):
                continue
            email = str(
                item.get("hme")
                or item.get("email")
                or item.get("alias")
                or item.get("address")
                or item.get("metaData", {}).get("hme")
                or ""
            ).strip().lower()
            if not email or "@" not in email:
                continue

            state = str(item.get("state") or item.get("status") or "").strip().lower()
            aliases.append({
                "email": email,
                "anonymousId": str(item.get("anonymousId") or item.get("id") or ""),
                "label": str(item.get("label") or item.get("metaData", {}).get("label") or ""),
                "note": str(item.get("note") or item.get("metaData", {}).get("note") or ""),
                "active": item.get("active", True) and item.get("isActive", True) and state not in ("inactive", "deleted"),
                "state": state,
                "createdAt": item.get("createTimestamp") or item.get("createdAt") or None,
            })

        # 排序：active 优先，按 email 字典序
        aliases.sort(key=lambda a: (not a["active"], a["email"]))
        return aliases

    # ---------- 邮件轮询 (maildomainws API) ----------

    def poll_mail_for_code(
        self,
        target_email: str,
        sender_filters: Optional[List[str]] = None,
        timeout: int = 120,
        interval: int = 5,
        exclude_codes: Optional[List[str]] = None,
        imap_user: str = "",
        imap_password: str = "",
    ) -> Optional[str]:
        """
        轮询 iCloud 邮箱找验证码 (IMAP)

        Args:
            target_email: 目标收件邮箱 (显示用)
            sender_filters: 发件人过滤
            timeout: 总超时秒数
            interval: 轮询间隔
            exclude_codes: 排除的验证码
            imap_user: iCloud 登录邮箱 (如 yangpang20@icloud.com)
            imap_password: app-specific password
        """
        if imap_user and imap_password:
            return self._poll_mail_imap(
                target_email, sender_filters, timeout, interval, exclude_codes,
                imap_user, imap_password,
            )
        return self._poll_mail_api(
            target_email, sender_filters, timeout, interval, exclude_codes
        )

    def _poll_mail_imap(
        self, target_email, sender_filters, timeout, interval, exclude_codes,
        imap_user, imap_password,
    ) -> Optional[str]:
        """IMAP 轮询 iCloud 邮箱 — 已验证通过"""
        import imaplib, quopri
        from html.parser import HTMLParser

        class _StripHTML(HTMLParser):
            def __init__(self): super().__init__(); self.text = ""
            def handle_data(self, d): self.text += d

        excluded = set(exclude_codes or [])
        filters = [f.lower() for f in (sender_filters or ["openai", "noreply", "verification"])]

        self._log(f"IMAP {imap_user} 开始轮询 ...")
        start = time.time()
        last_count = -1  # -1 表示第一轮，只记录基准不查邮件

        while time.time() - start < timeout:
            try:
                mail = imaplib.IMAP4_SSL("imap.mail.me.com", 993)
                mail.login(imap_user, imap_password)
                mail.select("INBOX")

                status, data = mail.search(None, "ALL")
                if status != "OK":
                    mail.logout()
                    time.sleep(interval)
                    continue

                msg_ids = data[0].split()
                current_count = len(msg_ids)

                # 第一轮: 只记基准数，不查邮件
                if last_count == -1:
                    last_count = current_count
                    self._log(f"IMAP 基准: {current_count} 封已有邮件")
                    mail.logout()
                    time.sleep(interval)
                    continue

                # 只检查新邮件
                if current_count > last_count:
                    new_ids = msg_ids[last_count:]
                    last_count = current_count
                    self._log(f"IMAP 发现 {len(new_ids)} 封新邮件")

                    for mid in reversed(new_ids):
                        status, msg_data = mail.fetch(mid, "(BODY[TEXT])")
                        if status != "OK":
                            continue

                        raw = b""
                        for item in msg_data:
                            if isinstance(item, tuple) and len(item) > 1:
                                raw = item[1] if isinstance(item[1], bytes) else raw
                                break

                        # 解码 quoted-printable
                        try:
                            text = quopri.decodestring(raw).decode("utf-8", errors="ignore")
                        except Exception:
                            text = raw.decode("utf-8", errors="ignore")

                        # 过滤发件人/主题关键字
                        lower = text.lower()
                        if not any(f in lower for f in filters):
                            continue

                        # 剥 HTML 提取验证码
                        parser = _StripHTML()
                        parser.feed(text)
                        plain = parser.text

                        codes = re.findall(r"\b(\d{6})\b", plain)
                        for code in codes:
                            if code not in excluded:
                                self._log(f"IMAP 找到验证码: {code}")
                                mail.logout()
                                return code

                mail.logout()
                time.sleep(interval)

            except Exception as e:
                self._log(f"IMAP 异常: {e}")
                time.sleep(interval)

        self._log(f"IMAP {timeout}s 超时")
        return None

    def _poll_mail_api(
        self, target_email: str, sender_filters: list, timeout: int,
        interval: int, exclude_codes: set,
    ) -> Optional[str]:
        excluded = set(exclude_codes or [])
        filters = [f.lower() for f in (sender_filters or [])]
        if not filters:
            filters = ["openai", "chatgpt", "noreply", "no-reply", "verification"]

        self._log(f"开始轮询 iCloud 邮箱（发件人过滤: {filters}, 超时 {timeout}s）...")
        start = time.time()
        seen_ids = set()

        while time.time() - start < timeout:
            try:
                # 用 maildomainws API 获取邮件列表
                messages = self._fetch_mail_messages()
                if not messages:
                    self._log(f"暂无新邮件，{interval}s 后重试...")
                    time.sleep(interval)
                    continue

                for msg in messages:
                    msg_id = str(msg.get("guid", ""))
                    if msg_id in seen_ids:
                        continue
                    seen_ids.add(msg_id)

                    sender = str(msg.get("from", "") or msg.get("sender", "")).lower()
                    subject = str(msg.get("subject", "")).lower()

                    # 检查发件人/主题是否匹配
                    match = any(f in sender or f in subject for f in filters)
                    if not match:
                        continue

                    self._log(f"匹配邮件: {subject[:60]} (from: {sender[:40]})")

                    # 获取邮件正文
                    body = self._fetch_mail_body(msg_id)
                    if not body:
                        continue

                    # 提取验证码
                    code = self._extract_code_from_text(body, excluded)
                    if code:
                        self._log(f"已找到验证码: {code}")
                        return code

            except Exception as e:
                self._log(f"轮询异常: {e}")

            time.sleep(interval)

        self._log(f"{timeout}s 内未找到验证码")
        return None

    def _fetch_mail_messages(self, limit: int = 20) -> List[Dict]:
        """获取 iCloud Mail 收件箱最近邮件"""
        # maildomainws 端点
        mail_url = f"{self._service_url}/maildomainws"
        try:
            response = self._request(
                "GET",
                f"{mail_url}/messages?folder=INBOX&limit={limit}",
                timeout=20,
            )
            return response.get("messages", []) if isinstance(response, dict) else []
        except Exception:
            # 回退到 webmail API
            try:
                response = self._request(
                    "GET",
                    f"https://www.{self.host}/mail/",
                    timeout=20,
                )
                return []
            except Exception:
                return []

    def _fetch_mail_body(self, msg_id: str) -> str:
        """获取邮件正文"""
        mail_url = f"{self._service_url}/maildomainws"
        try:
            response = self._request(
                "GET",
                f"{mail_url}/messages/{msg_id}",
                timeout=20,
            )
            if isinstance(response, dict):
                return str(response.get("body", "") or response.get("textBody", "") or "")
            return ""
        except Exception:
            return ""

    @staticmethod
    def _extract_code_from_text(text: str, excluded: set) -> Optional[str]:
        """从邮件文本提取 6 位验证码"""
        text = text or ""

        # 中文模式
        m = re.search(r"(?:代码为|验证码[^0-9]*?)\s*[:：]?\s*(\d{6})", text)
        if m:
            code = m.group(1)
            if code not in excluded:
                return code

        # 英文模式
        m = re.search(r"(?:log-?in\s+code|enter\s+this\s+code|verification\s+code)[^0-9]{0,24}(\d{6})", text, re.I)
        if m:
            code = m.group(1)
            if code not in excluded:
                return code

        m = re.search(r"code[:\s]+is[:\s]+(\d{6})|code[:\s]+(\d{6})", text, re.I)
        if m:
            code = m.group(1) or m.group(2)
            if code not in excluded:
                return code

        # 通用 6 位数字
        matches = re.findall(r"\b(\d{6})\b", text)
        for code in matches:
            if code not in excluded:
                return code

        return None


# ============================================================
# CLI
# ============================================================

def _load_cookies(args) -> Dict[str, str]:
    """根据命令行参数加载 cookies"""
    if args.cookies:
        with open(args.cookies, "r", encoding="utf-8") as f:
            return json.load(f)
    # 自动从 Chrome 提取
    print("[*] 正在从 Chrome 提取 iCloud cookies...")
    cookies = extract_chrome_cookies()
    if not cookies:
        raise RuntimeError("未提取到 iCloud cookies，请先在 Chrome 登录 icloud.com")
    print(f"[+] 已提取 {len(cookies)} 个 cookie")
    return cookies


def _validate_cookies(cookies: Dict[str, str]):
    """检查是否包含必要 cookie"""
    key_names = [k.lower() for k in cookies.keys()]
    has_web_auth = any("webauth" in k for k in key_names)
    has_session = any(k in key_names for k in ("dssid2", "dssid", "session"))
    if not has_web_auth and not has_session:
        print("[!] 警告：未检测到典型的 iCloud 鉴权 cookie (X-APPLE-WEBAUTH-* 或 session cookie)")
        print("[!] 如果后续请求失败，请确认已在 Chrome 登录 https://www.icloud.com")


def cmd_list(args):
    cookies = _load_cookies(args)
    _validate_cookies(cookies)
    client = ICloudHME(cookies, host=args.host, verbose=args.verbose)
    aliases = client.list_aliases()
    print(f"\n共 {len(aliases)} 个 Hide My Email 别名:\n")
    for a in aliases:
        status = "[ACTIVE]" if a["active"] else "[INACTIVE]"
        print(f"  {status} {a['email']}")
        if a["label"]:
            print(f"          label: {a['label']}")
        if a["anonymousId"]:
            print(f"          id: {a['anonymousId']}")
        if a["createdAt"]:
            print(f"          created: {a['createdAt']}")
        print()


def cmd_generate(args):
    cookies = _load_cookies(args)
    _validate_cookies(cookies)
    client = ICloudHME(cookies, host=args.host, verbose=args.verbose)
    alias = client.create_alias(args.label)
    print(f"\n[+] 新别名已创建: {alias}")


def cmd_delete(args):
    cookies = _load_cookies(args)
    _validate_cookies(cookies)
    client = ICloudHME(cookies, host=args.host, verbose=args.verbose)

    if args.email:
        # 先列出找到 anonymousId
        aliases = client.list_aliases()
        target = args.email.strip().lower()
        found = next((a for a in aliases if a["email"] == target), None)
        if not found:
            print(f"[!] 未找到别名: {target}")
            sys.exit(1)
        anonymous_id = found["anonymousId"]
        if not anonymous_id:
            print(f"[!] {target} 缺少 anonymousId，无法删除")
            sys.exit(1)
        client.delete(anonymous_id)
        print(f"[+] 已删除: {target}")
    elif args.id:
        client.delete(args.id)
        print(f"[+] 已删除: {args.id}")
    else:
        print("[!] 请指定 --email 或 --id")
        sys.exit(1)


def cmd_export_cookies(args):
    cookies = extract_chrome_cookies()
    output = args.output or "icloud_cookies.json"
    with open(output, "w", encoding="utf-8") as f:
        json.dump(cookies, f, indent=2, ensure_ascii=False)
    print(f"[+] 已导出 {len(cookies)} 个 cookie 到 {output}")


def main():
    parser = argparse.ArgumentParser(
        description="iCloud Hide My Email — 纯协议操作工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # list
    p_list = sub.add_parser("list", help="列出所有 Hide My Email 别名")
    p_list.add_argument("--cookies", help="cookies.json 文件路径")
    p_list.add_argument("--host", default="icloud.com", choices=["icloud.com", "icloud.com.cn"])
    p_list.add_argument("--verbose", "-v", action="store_true")

    # generate
    p_gen = sub.add_parser("generate", help="创建新的 Hide My Email 别名")
    p_gen.add_argument("--cookies", help="cookies.json 文件路径")
    p_gen.add_argument("--host", default="icloud.com", choices=["icloud.com", "icloud.com.cn"])
    p_gen.add_argument("--label", help="别名标签（默认: MultiPage YYYY-MM-DD）")
    p_gen.add_argument("--verbose", "-v", action="store_true")

    # delete
    p_del = sub.add_parser("delete", help="删除 Hide My Email 别名")
    p_del.add_argument("--cookies", help="cookies.json 文件路径")
    p_del.add_argument("--host", default="icloud.com", choices=["icloud.com", "icloud.com.cn"])
    p_del.add_argument("--email", help="要删除的别名邮箱地址")
    p_del.add_argument("--id", help="要删除的别名的 anonymousId")
    p_del.add_argument("--verbose", "-v", action="store_true")

    # export-cookies
    p_exp = sub.add_parser("export-cookies", help="从 Chrome 导出 cookies 到文件")
    p_exp.add_argument("--output", "-o", default="icloud_cookies.json")

    args = parser.parse_args()

    try:
        if args.command == "list":
            cmd_list(args)
        elif args.command == "generate":
            cmd_generate(args)
        elif args.command == "delete":
            cmd_delete(args)
        elif args.command == "export-cookies":
            cmd_export_cookies(args)
    except RuntimeError as e:
        print(f"[!] {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] 已中断")
        sys.exit(1)


if __name__ == "__main__":
    main()
