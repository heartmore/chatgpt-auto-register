#!/usr/bin/env python3
"""
ChatGPT Auto Register - Fully automated phone-based registration.

Combines three independent techniques:
  1. curl_cffi   - Chrome TLS fingerprint (bypasses Cloudflare network layer)
  2. Sentinel    - FNV-1a Proof-of-Work (bypasses JS anti-bot challenges)
  3. SMSBower    - Automated SMS verification code retrieval

Usage:
  python auto_register.py                  # interactive mode
  python auto_register.py -n 5             # register 5 accounts
  python auto_register.py --gui            # start web GUI
"""

import argparse
import json
import os
import secrets
import string
import sys
import time as _time
from datetime import datetime
from pathlib import Path

from chatgpt_register import ChatGPTRegister
from smsbower import SmsBower

# ============================================================
# 随机资料
# ============================================================

_FIRST_NAMES = [
    "James","John","Robert","Michael","William","David","Richard","Joseph","Thomas","Daniel",
    "Matthew","Anthony","Mark","Christopher","Paul","Steven","Andrew","Joshua","Kenneth","Kevin",
    "Brian","George","Timothy","Edward","Ronald","Jason","Jeffrey","Ryan","Jacob","Gary",
    "Nicholas","Eric","Stephen","Jonathan","Larry","Justin","Scott","Brandon","Frank","Raymond",
]
_LAST_NAMES = [
    "Smith","Johnson","Williams","Brown","Jones","Miller","Davis","Garcia","Rodriguez","Wilson",
    "Martinez","Anderson","Taylor","Thomas","Hernandez","Moore","Martin","Jackson","Thompson","White",
    "Lopez","Lee","Gonzalez","Harris","Clark","Lewis","Robinson","Walker","Perez","Hall",
    "Young","Allen","Sanchez","Wright","King","Scott","Green","Baker","Adams","Nelson",
]

def random_name() -> str:
    return f"{secrets.choice(_FIRST_NAMES)} {secrets.choice(_LAST_NAMES)}"

def random_birthdate() -> str:
    y = secrets.choice(range(1982, 2003))
    m = secrets.choice(range(1, 13))
    d = secrets.choice(range(1, 29))
    return f"{y:04d}-{m:02d}-{d:02d}"

def random_password(length: int = 16) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%"
    return "".join(secrets.choice(chars) for _ in range(length))

def _retry_call(fn, max_retries=2, delay=2, label=""):
    """重试包装器 — 失败自动重试"""
    for attempt in range(max_retries + 1):
        try:
            return fn()
        except Exception as e:
            if attempt >= max_retries:
                raise
            if label:
                print(f"  [{label}] 失败 ({e})，{delay}s 后重试 ({attempt+1}/{max_retries})...")
            _time.sleep(delay)

# ============================================================
# 配置
# ============================================================

def load_config(path: str = None) -> dict:
    config = {
        "smsbower": {"api_key": ""},
        "register": {"password": "", "name": "A", "birthdate": "2000-01-01"},
        "proxy": "",
        "country": "151",
        "service": "dr",
        "code_timeout": 30,
    }
    candidates = [path, "config.json", str(Path(__file__).parent / "config.json")]
    found = {}
    for p in candidates:
        if p and Path(p).exists():
            with open(p, "r", encoding="utf-8") as f:
                found = json.load(f)
            for k in ["smsbower", "register"]:
                if k in found:
                    config[k].update(found[k])
            for k in ["proxy", "country", "service", "code_timeout"]:
                if k in found:
                    config[k] = found[k]
            # Passthrough extra keys (e.g. "gui")
            for k, v in found.items():
                if k not in {"smsbower", "register", "proxy", "country", "service", "code_timeout"}:
                    config[k] = v
            break
    if os.environ.get("SMSBOWER_KEY"):
        config["smsbower"]["api_key"] = os.environ["SMSBOWER_KEY"]
    proxy_env = os.environ.get("PROXY") or os.environ.get("HTTPS_PROXY")
    if proxy_env:
        config["proxy"] = proxy_env
    return config

# ============================================================
# 注册核心
# ============================================================

def register_one(
    sms: SmsBower,
    config: dict,
    provider_ids: str = "",
    max_price: str = "",
    verbose: bool = True,
    step_retries: int = 2,
    create_account_max_retries: int = 20,
) -> dict:
    service = config["service"]
    country = config["country"]
    reg_cfg = config["register"]

    password = reg_cfg["password"] or random_password()
    name = reg_cfg.get("name") or random_name()
    birthdate = reg_cfg.get("birthdate") or random_birthdate()
    if name == "A" and birthdate == "2000-01-01":
        name = random_name()
        birthdate = random_birthdate()

    phone = "?"
    aid = ""
    reg = None
    sr = step_retries

    try:
        aid, phone_raw = sms.get_number(service=service, country=country, provider_ids=provider_ids, max_price=max_price)
        phone = "+" + phone_raw if not phone_raw.startswith("+") else phone_raw
        if verbose:
            print(f"  手机号: {phone}  激活ID: {aid}")
        sms.set_ready()

        reg = ChatGPTRegister(proxy=config["proxy"])

        _retry_call(lambda: reg.visit(), sr, label="访问首页")
        csrf = _retry_call(lambda: reg.get_csrf(), sr, label="CSRF")
        redirect = _retry_call(lambda: reg.signin(phone, csrf), sr, label="发起登录")
        _retry_call(lambda: reg.jump_to_auth(redirect), sr, label="OAuth跳转")
        result = _retry_call(lambda: reg.register_user(phone, password), sr, label="注册")

        continue_url = result.get("continue_url", "")
        if not continue_url:
            sms.cancel()
            return {"ok": False, "phone": phone, "error": f"注册被拒(status={result.get('_status')})"}

        _retry_call(lambda: reg.send_otp(continue_url), sr, label="发送验证码")
        if verbose:
            print(f"  验证码已发送到 {phone}")

        code = sms.wait_code(timeout=config["code_timeout"])
        if not code:
            sms.cancel()
            return {"ok": False, "phone": phone, "error": "验证码超时"}

        if verbose:
            print(f"  收到验证码: {code}")

        result = _retry_call(lambda: reg.validate_otp(code), sr, label="校验验证码")
        continue_url = result.get("continue_url", "")
        if not continue_url:
            sms.cancel()
            return {"ok": False, "phone": phone, "error": f"验证码校验失败(status={result.get('_status')})"}

        # ============================================================
        # 先访问 about-you 页面建立会话上下文
        # ============================================================
        _retry_call(lambda: reg.visit_about_you(continue_url), sr, label="访问about-you")

        # ============================================================
        # 创建账户 (用户名+生日) — 最多重试 create_account_max_retries 次
        # ============================================================
        last_create_error = ""
        for ca_attempt in range(create_account_max_retries):
            ca_name = random_name() if ca_attempt > 0 else name
            ca_birthdate = random_birthdate() if ca_attempt > 0 else birthdate
            if verbose:
                print(f"  创建账户 [{ca_attempt+1}/{create_account_max_retries}]: name={ca_name} birthdate={ca_birthdate}")

            result = reg.create_account(ca_name, ca_birthdate)
            callback_url = result.get("continue_url", "")
            if callback_url:
                name = ca_name
                birthdate = ca_birthdate
                break

            last_create_error = result.get("_body", "") or f"status={result.get('_status')}"
            if verbose:
                detail = last_create_error[:200]
                print(f"  创建账户失败 [{ca_attempt+1}]: {detail}")
            if ca_attempt < create_account_max_retries - 1:
                _time.sleep(1)

        if not callback_url:
            sms.cancel()
            return {"ok": False, "phone": phone, "error": f"创建账户失败(已重试{create_account_max_retries}次): {last_create_error[:200]}"}

        token = _retry_call(lambda: reg.oauth_callback(callback_url), sr, label="OAuth回调")
        access_token = _retry_call(lambda: reg.get_access_token(), sr, label="获取Token")
        sms.complete()

        return {
            "ok": True, "phone": phone, "password": password,
            "name": name, "birthdate": birthdate,
            "session_token": token, "access_token": access_token, "activation_id": aid,
        }

    except Exception as e:
        try: sms.cancel()
        except Exception: pass
        return {"ok": False, "phone": phone, "error": str(e)}

# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="ChatGPT 自动注册")
    parser.add_argument("--config", "-c", type=str, help="配置文件路径")
    parser.add_argument("--count", "-n", type=int, default=1, help="目标成功数量")
    parser.add_argument("--country", type=str, help="国家 ID (默认 151=智利)")
    parser.add_argument("--service", type=str, help="服务代码 (默认 dr=OpenAI)")
    parser.add_argument("--provider", type=str, default="", help="指定运营商 ID")
    parser.add_argument("--max-price", type=str, default="", help="最高价格")
    parser.add_argument("--proxy", type=str, help="代理地址")
    parser.add_argument("--password", type=str, help="密码 (留空随机)")
    parser.add_argument("--retry", "-r", type=int, default=2, help="各步骤重试次数")
    parser.add_argument("--create-retry", type=int, default=20, help="创建账户重试次数 (默认20)")
    parser.add_argument("--output", "-o", type=str, default="register_results.json")
    parser.add_argument("--gui", action="store_true", help="启动 Web GUI")
    # Phase 2
    parser.add_argument("--phase2", action="store_true")
    parser.add_argument("--bind-email", type=str)
    parser.add_argument("--icloud-cookies", type=str)
    parser.add_argument("--sub2api-url", type=str)
    parser.add_argument("--sub2api-email", type=str)
    parser.add_argument("--sub2api-pwd", type=str)
    parser.add_argument("--sub2api-proxy-id", type=int, default=0)
    parser.add_argument("--sub2api-group-id", type=int, default=1)

    args = parser.parse_args()

    if args.gui:
        from web_gui import start_gui
        start_gui()
        return

    config = load_config(args.config)
    if args.country: config["country"] = args.country
    if args.service: config["service"] = args.service
    if args.proxy: config["proxy"] = args.proxy
    if args.password: config["register"]["password"] = args.password

    if not config["smsbower"]["api_key"]:
        print("错误: 需要 SMSBower API Key.")
        sys.exit(1)

    sms = SmsBower(config["smsbower"]["api_key"])
    bal = sms.balance()
    try:
        pid, price = sms.get_cheapest_provider(config["service"], config["country"])
    except Exception:
        pid, price = "?", 0
    print(f"余额: {bal}  国家: {config['country']}  运营商: {pid} (${price:.4f})")
    print(f"代理: {config['proxy'] or '直连'}  目标: {args.count}个")
    print("-" * 50)

    results = []
    ok_count = 0
    attempt = 0
    max_attempts = args.count * 10

    while ok_count < args.count and attempt < max_attempts:
        attempt += 1
        print(f"\n第 {attempt} 次 [{ok_count}/{args.count}]")
        try:
            result = register_one(sms, config, provider_ids=args.provider,
                                  max_price=args.max_price, step_retries=args.retry,
                                  create_account_max_retries=args.create_retry,
                                  verbose=True)
        except Exception as e:
            result = {"ok": False, "phone": "?", "error": str(e)}
        results.append(result)
        if result["ok"]:
            ok_count += 1
            phone = result.get("phone", "?")
            token = result.get("session_token", "")
            at = result.get("access_token", "")
            print(f"  成功: {phone}  名称: {result.get('name','?')}")
            if args.phase2 and args.sub2api_url:
                try:
                    from phase2_codex import upload_session
                    upload_session(token, args.bind_email or "", args.sub2api_url,
                                   args.sub2api_email, args.sub2api_pwd,
                                   sub2api_proxy_id=args.sub2api_proxy_id,
                                   group_ids=[args.sub2api_group_id], access_token=at)
                    print(f"  已上传到 SUB2API")
                except Exception as e:
                    print(f"  上传失败: {e}")
        else:
            print(f"  失败: {result.get('phone','?')} - {result.get('error','?')}")

    if ok_count < args.count:
        print(f"\n注意: 仅成功 {ok_count}/{args.count} (已达最大尝试次数)")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    raw = Path(args.output)
    output_path = raw.parent / f"{raw.stem}_{ts}{raw.suffix}"
    safe = [dict(r) for r in results if r.get("ok")]
    output_path.write_text(json.dumps(safe, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\n已保存 {len(safe)} 条结果到 {output_path}")

if __name__ == "__main__":
    main()
