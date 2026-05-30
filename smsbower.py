"""
SMSBower API client for automated SMS verification code retrieval.
API docs: https://smsbower.app/api?page=client
"""

import time
import json
from typing import Optional
import requests


SMSBOWER_API = "https://smsbower.page/stubs/handler_api.php"


def _call(api_key: str, params: dict) -> str:
    params["api_key"] = api_key
    r = requests.get(SMSBOWER_API, params=params, timeout=30)
    text = r.text.strip()
    # SMSBower sometimes returns JSON errors instead of text
    if text.startswith("{") and "message" in text:
        try:
            data = json.loads(text)
            if data.get("message") == "No access":
                raise RuntimeError("SMSBower: API key invalid or no access")
        except json.JSONDecodeError:
            pass
    return text



class SmsBower:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.activation_id: Optional[str] = None
        self.phone: Optional[str] = None

    def balance(self) -> str:
        return _call(self.api_key, {"action": "getBalance"})

    def list_services(self) -> list[dict]:
        r = requests.get(
            SMSBOWER_API,
            params={"api_key": self.api_key, "action": "getServicesList"},
            timeout=15,
        )
        return r.json().get("services", [])

    def find_service(self, keyword: str) -> list[dict]:
        services = self.list_services()
        kw = keyword.lower()
        return [
            s for s in services
            if kw in s.get("code", "").lower()
            or kw in s.get("name", "").lower()
        ]

    def get_cheapest_provider(
        self, service: str = "dr", country: str = "151"
    ) -> tuple[str, float]:
        r = requests.get(
            SMSBOWER_API,
            params={
                "api_key": self.api_key,
                "action": "getPricesV3",
                "service": service,
                "country": country,
            },
            timeout=15,
        )
        data = r.json()
        providers = data.get(country, {}).get(service, {})
        cheapest, cheapest_price = "", 999.0
        for pid, info in providers.items():
            price = float(info.get("price", 999))
            if price < cheapest_price:
                cheapest_price = price
                cheapest = pid
        return cheapest, cheapest_price

    def get_number(
        self,
        service: str = "dr",
        country: str = "151",
        provider_ids: str = "",
        max_price: str = "",
    ) -> tuple[str, str]:
        params = {"action": "getNumber", "service": service, "country": country}
        if provider_ids:
            params["providerIds"] = provider_ids
        if max_price:
            params["maxPrice"] = max_price
        resp = _call(self.api_key, params)

        if resp.startswith("ACCESS_NUMBER:"):
            _, aid, phone = resp.split(":")
            self.activation_id = aid
            self.phone = phone
            return aid, phone
        raise RuntimeError(f"getNumber failed: {resp}")

    def set_ready(self):
        _call(self.api_key, {
            "action": "setStatus", "status": "1", "id": self.activation_id
        })

    def wait_code(self, timeout: int = 300, interval: int = 3) -> Optional[str]:
        if not self.activation_id:
            raise RuntimeError("No active activation")
        started = time.time()
        while time.time() - started < timeout:
            resp = _call(self.api_key, {
                "action": "getStatus", "id": self.activation_id
            })
            if resp.startswith("STATUS_OK:"):
                return resp.split(":", 1)[1].strip()
            elif resp == "STATUS_CANCEL":
                raise RuntimeError("Activation cancelled (may have timed out)")
            time.sleep(interval)
        return None

    def complete(self):
        _call(self.api_key, {
            "action": "setStatus", "status": "6", "id": self.activation_id
        })

    def cancel(self):
        try:
            _call(self.api_key, {
                "action": "setStatus", "status": "8", "id": self.activation_id
            })
        except Exception:
            pass
