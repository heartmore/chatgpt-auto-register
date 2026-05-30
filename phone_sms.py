#!/usr/bin/env python3
"""
手机接码平台 — 纯协议实现
支持 hero-sms、5sim、nexsms 三种平台

用法:
    from phone_sms import PhoneSMS
    sms = PhoneSMS(provider="hero-sms", api_key="your_key")
    activation = sms.get_number(country="thailand")  # 获取号码
    code = sms.wait_for_code(activation.id, timeout=120)  # 等验证码
"""

import time
import requests
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field


# ============================================================
# 数据模型
# ============================================================

@dataclass
class Activation:
    id: str
    phone: str
    country: str
    service: str
    status: str = "pending"
    code: Optional[str] = None


# ============================================================
# hero-sms 平台
# ============================================================

HERO_SMS_BASE = "https://hero-sms.com/stubs/handler_api.php"
HERO_SMS_SERVICE_CODES = {
    "openai": "dr",
    "chatgpt": "dr",
    "google": "go",
    "telegram": "tg",
}
HERO_SMS_COUNTRIES = {
    "thailand": 52,
    "indonesia": 6,
    "usa": 187,
    "uk": 16,
    "japan": 151,
    "germany": 43,
    "france": 73,
    "vietnam": 10,
}


class HeroSMS:
    """hero-sms.com API"""

    def __init__(self, api_key: str, base_url: str = HERO_SMS_BASE):
        self.api_key = api_key
        self.base_url = base_url

    def _call(self, params: Dict[str, str]) -> str:
        params["api_key"] = self.api_key
        resp = requests.get(self.base_url, params=params, timeout=30)
        return resp.text.strip()

    def get_balance(self) -> float:
        params = {"action": "getBalance"}
        result = self._call(params)
        if result.startswith("ACCESS_BALANCE:"):
            return float(result.split(":")[1])
        raise RuntimeError(f"查询余额失败: {result}")

    def get_number(
        self,
        service: str = "dr",
        country: str = "thailand",
        operator: Optional[str] = None,
    ) -> Activation:
        """
        获取手机号
        service: 服务代码 (dr=OpenAI, go=Google 等)
        country: 国家名或 ID
        """
        country_id = HERO_SMS_COUNTRIES.get(country, country)
        params = {
            "action": "getNumber",
            "service": service,
            "country": str(country_id),
        }
        if operator:
            params["operator"] = operator

        result = self._call(params)
        # 返回格式: ACCESS_NUMBER:activationId:phoneNumber
        if result.startswith("ACCESS_NUMBER:"):
            parts = result.split(":")
            act_id = parts[1]
            phone = parts[2]
            return Activation(
                id=act_id,
                phone=phone,
                country=str(country),
                service=service,
                status="waiting",
            )
        raise RuntimeError(f"获取号码失败: {result}")

    def get_status(self, activation_id: str) -> str:
        """
        查询激活状态
        返回: STATUS_WAIT_CODE | STATUS_OK:code | STATUS_CANCEL | STATUS_WAIT_RESEND
        """
        result = self._call({
            "action": "getStatus",
            "id": activation_id,
        })
        return result

    def wait_for_code(
        self,
        activation_id: str,
        timeout: int = 180,
        interval: int = 5,
        verbose: bool = True,
    ) -> Optional[str]:
        """轮询等待验证码，超时返回 None"""
        start = time.time()
        while time.time() - start < timeout:
            status = self.get_status(activation_id)
            if verbose:
                print(f"  [hero-sms] 轮询 {activation_id}: {status}")

            if status.startswith("STATUS_OK:"):
                code = status.split(":", 1)[1]
                return code
            elif status == "STATUS_CANCEL":
                return None
            elif status == "STATUS_WAIT_RESEND":
                # 等待重发
                time.sleep(interval)
            else:
                time.sleep(interval)

        self.cancel(activation_id)
        return None

    def cancel(self, activation_id: str) -> bool:
        """取消激活（释放号码）"""
        result = self._call({
            "action": "setStatus",
            "id": activation_id,
            "status": "8",  # 取消
        })
        return "ACCESS_CANCEL" in result

    def finish(self, activation_id: str) -> bool:
        """标记激活完成"""
        result = self._call({
            "action": "setStatus",
            "id": activation_id,
            "status": "6",  # 完成
        })
        return "ACCESS_ACTIVATION" in result


# ============================================================
# 5sim.net 平台
# ============================================================

FIVE_SIM_BASE = "https://5sim.net/v1"
FIVE_SIM_PRODUCTS = {
    "openai": "openai",
    "chatgpt": "openai",
}


class FiveSim:
    """5sim.net API"""

    def __init__(self, api_key: str, base_url: str = FIVE_SIM_BASE):
        self.api_key = api_key
        self.base_url = base_url

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }

    def get_balance(self) -> Dict:
        resp = requests.get(
            f"{self.base_url}/user/profile",
            headers=self._headers(),
            timeout=30,
        )
        data = resp.json()
        return data

    def get_number(
        self,
        product: str = "openai",
        country: str = "thailand",
        operator: str = "any",
    ) -> Activation:
        """
        购买激活号码
        country: thailand, vietnam, indonesia
        """
        resp = requests.get(
            f"{self.base_url}/user/buy/activation/{country}/{operator}/{product}",
            headers=self._headers(),
            timeout=30,
        )
        data = resp.json()
        if not data.get("id"):
            raise RuntimeError(f"5sim 获取号码失败: {data}")

        return Activation(
            id=str(data["id"]),
            phone=str(data.get("phone", "")),
            country=country,
            service=product,
            status="waiting",
        )

    def check_sms(self, activation_id: str) -> List[Dict]:
        """检查短信列表"""
        resp = requests.get(
            f"{self.base_url}/user/check/{activation_id}",
            headers=self._headers(),
            timeout=30,
        )
        return resp.json()

    def wait_for_code(
        self,
        activation_id: str,
        timeout: int = 180,
        interval: int = 5,
        verbose: bool = True,
    ) -> Optional[str]:
        """轮询等待验证码"""
        start = time.time()
        while time.time() - start < timeout:
            messages = self.check_sms(activation_id)
            if verbose:
                print(f"  [5sim] 轮询 {activation_id}: {len(messages)} 条短信")

            for msg in messages:
                text = str(msg.get("text", "") or msg.get("sms", "") or "")
                code = msg.get("code", "")
                if code:
                    return str(code)
                # 尝试从文本提取 6 位数字
                import re
                match = re.search(r"\b(\d{6})\b", text)
                if match:
                    return match.group(1)

            time.sleep(interval)

        self.cancel(activation_id)
        return None

    def cancel(self, activation_id: str) -> bool:
        resp = requests.get(
            f"{self.base_url}/user/cancel/{activation_id}",
            headers=self._headers(),
            timeout=30,
        )
        return resp.status_code == 200

    def finish(self, activation_id: str) -> bool:
        resp = requests.get(
            f"{self.base_url}/user/finish/{activation_id}",
            headers=self._headers(),
            timeout=30,
        )
        return resp.status_code == 200


# ============================================================
# SMSBower 平台 (API 与 hero-sms 兼容)
# ============================================================

SMSBOWER_BASE = "https://smsbower.page/stubs/handler_api.php"

class SmsBower(HeroSMS):
    """SMSBower — API 与 hero-sms 完全兼容，仅 base URL 不同"""
    def __init__(self, api_key: str):
        super().__init__(api_key, base_url=SMSBOWER_BASE)


# ============================================================
# 统一接口
# ============================================================

class PhoneSMS:
    """统一的接码平台接口"""

    PROVIDERS = {
        "hero-sms": HeroSMS,
        "smsbower": SmsBower,
        "5sim": FiveSim,
    }

    def __init__(self, provider: str = "hero-sms", api_key: str = ""):
        if provider not in self.PROVIDERS:
            raise ValueError(f"不支持的接码平台: {provider}，可选: {list(self.PROVIDERS)}")
        self.provider = provider
        self.client = self.PROVIDERS[provider](api_key)

    def get_number(
        self,
        service: str = "openai",
        country: str = "thailand",
    ) -> Activation:
        return self.client.get_number(service=service, country=country)

    def wait_for_code(
        self,
        activation_id: str,
        timeout: int = 180,
        verbose: bool = True,
    ) -> Optional[str]:
        return self.client.wait_for_code(activation_id, timeout=timeout, verbose=verbose)

    def cancel(self, activation_id: str):
        self.client.cancel(activation_id)

    def finish(self, activation_id: str):
        self.client.finish(activation_id)


# ============================================================
# CLI 测试
# ============================================================

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--provider", default="hero-sms", choices=["hero-sms", "5sim"])
    p.add_argument("--api-key", required=True)
    p.add_argument("--command", default="balance", choices=["balance", "get-number", "wait-code"])
    p.add_argument("--country", default="thailand")
    p.add_argument("--service", default="dr")
    p.add_argument("--activation-id", default="")
    args = p.parse_args()

    sms = PhoneSMS(args.provider, args.api_key)
    if args.command == "balance":
        if args.provider == "hero-sms":
            print(f"余额: {sms.client.get_balance()}")
        else:
            print(sms.client.get_balance())
    elif args.command == "get-number":
        act = sms.get_number(args.service, args.country)
        print(f"ID={act.id} 号码={act.phone}")
    elif args.command == "wait-code":
        code = sms.wait_for_code(args.activation_id, timeout=180)
        print(f"验证码: {code}")
