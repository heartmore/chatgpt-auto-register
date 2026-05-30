# ChatGPT 自动注册机

[![Python](https://img.shields.io/badge/Python-3.8+-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> 纯协议逆向实现的 ChatGPT 手机号全自动注册工具。无需浏览器，内存占用 ~20MB，一行命令拿号。

基于 [Anything Analyzer](https://github.com/Mouseww/anything-analyzer) 抓包逆向 ChatGPT 手机注册协议，融合 [open-reg-auto](https://github.com/wuchenwl/open-reg-auto) 的 Sentinel 反爬方案和 SMSBower 接码平台，实现从获取号码到拿到 Session Token 的端到端自动化。

**功能特点：**
- 🚀 纯协议实现，不依赖浏览器，20MB 内存
- 🔐 curl_cffi 伪装 Chrome TLS 指纹绕过 Cloudflare
- 🛡️ Sentinel FNV-1a 工作量证明绕过 JavaScript 反爬
- 📱 SMSBower 全自动接码，无需手动收短信
- ⚙️ 支持命令行参数、配置文件、环境变量三种配置方式

**交流群：1060714372**

---

# ChatGPT Auto Register

Fully automated ChatGPT phone-based registration using protocol-level reverse engineering.

No browser required. ~20MB memory. One command to get a verified account.

## How it works

Three independent techniques combined into one pipeline:

| Layer | Technique | Bypasses |
|-------|-----------|----------|
| **Network** | [curl_cffi](https://github.com/lexiforest/curl_cffi) | Chrome TLS fingerprint → Cloudflare |
| **Anti-bot** | Sentinel PoW (FNV-1a) | JS challenge → auth.openai.com |
| **SMS** | [SMSBower](https://smsbower.app) API | Automatic OTP retrieval |

Based on reverse engineering via [Anything Analyzer](https://github.com/Mouseww/anything-analyzer) and [open-reg-auto](https://github.com/wuchenwl/open-reg-auto).

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure

```bash
cp config.example.json config.json
```

Edit `config.json` - fill in your SMSBower API key:

```json
{
    "smsbower": {
        "api_key": "YOUR_KEY_HERE"
    },
    "proxy": "socks5h://127.0.0.1:10808",
    "country": "151"
}
```

Or use environment variables:
```bash
set SMSBOWER_KEY=YOUR_KEY_HERE
set HTTPS_PROXY=socks5h://127.0.0.1:10808
```

### 3. Run

```bash
# Interactive mode
python auto_register.py

# Register 3 accounts
python auto_register.py -n 3

# Use specific country
python auto_register.py --country 151 --service dr

# With custom password
python auto_register.py --password "MyPassword123"
```

## Registration flow

```
SMSBower                   ChatGPT Protocol
─────────                  ────────────────
getNumber() ──────┐
                   │
                   ├──► GET  chatgpt.com/auth/login        (cookies)
                   ├──► GET  /api/auth/csrf               (csrf token)
                   ├──► POST /api/auth/signin/openai       (initiate)
                   ├──► GET  auth.openai.com/authorize     (OAuth redirect)
                   ├──► GET  /create-account/password      (session est.)
Phone number ──────┤
                   ├──► POST /api/accounts/user/register   (phone + password)
                   ├──► GET  /api/accounts/phone-otp/send  (trigger SMS)
wait_code() ◄──────┤
                   │
SMS received ──────┘
                   ├──► POST /api/accounts/phone-otp/validate (verify code)
                   ├──► POST /api/accounts/create_account    (profile)
                   └──► GET  /api/auth/callback/openai       (session token)
```

## Configuration reference

| Key | Default | Description |
|-----|---------|-------------|
| `smsbower.api_key` | (required) | SMSBower API key |
| `register.password` | (random) | Account password (auto-generated if empty) |
| `register.name` | `A` | Display name |
| `register.birthdate` | `2000-01-01` | Date of birth |
| `proxy` | (direct) | Proxy URL, e.g. `socks5h://127.0.0.1:10808` |
| `country` | `151` | SMSBower country ID (151=Chile, 33=Colombia) |
| `service` | `dr` | SMSBower service code (dr=OpenAI/ChatGPT) |
| `code_timeout` | `300` | Seconds to wait for SMS code |

### Verified countries

| Country | ID | Price | Status |
|---------|----|-------|--------|
| Chile | 151 | ~$0.04 | Working |
| Colombia | 33 | ~$0.014 | SMS not received |

More countries can be tested by changing the `country` parameter. Run with `--country <id>` to try different regions.

## Proxy setup

If you are behind a firewall, use `socks5h://` (DNS through proxy) for V2RayN/Clash:

```bash
python auto_register.py --proxy socks5h://127.0.0.1:10808
```

## 全链路: Phase 1 + Phase 2

### Phase 1: 手机号注册 ChatGPT

```bash
# CLI
python auto_register.py -n 5 --country 151 --max-price 0.039

# Web GUI
python auto_register.py --gui
# 浏览器打开 http://127.0.0.1:8080
```

### Phase 2: OAuth 登录 + 绑邮箱 + 上传 SUB2API

```bash
# 从 SUB2API 生成 OAuth URL
python openai_oauth.py --sub2api-url https://xxx.com --sub2api-email a@b.com --sub2api-password xxx

# 完整后半段 (需先有 session_token)
python test_pipeline.py
```

### 全链路自动编排

```bash
python openai_pipeline.py run \
  --sms-key YOUR_SMSBOWER_KEY \
  --icloud-cookies cookies.json \
  --sub2api-url https://xxx.com \
  --sub2api-email a@b.com \
  --sub2api-password xxx
```

## Project structure

```
chatgpt-auto-register/
├── auto_register.py       # Phase 1 CLI + register_one engine
├── chatgpt_register.py    # Core: curl_cffi + Sentinel
├── smsbower.py            # SMSBower API client
├── sentinel.py            # OpenAI Sentinel anti-bot
├── web_gui.py             # Flask web GUI
│
├── openai_bind_email.py   # Phase 2: OAuth login -> bind email -> consent -> code
├── openai_oauth.py        # OAuth token exchange
├── openai_pipeline.py     # Full pipeline orchestrator
├── phone_sms.py           # SMSBower / hero-sms / 5sim SMS providers
├── icloud_hme.py          # iCloud Hide My Email + IMAP polling
├── phase2_codex.py        # Phase 2 thin wrapper
├── test_pipeline.py       # Daily-use entry point
│
├── config.example.json    # Configuration template
├── cookies.json           # iCloud cookies (gitignored)
├── requirements.txt       # Python dependencies
├── register_results.json  # Output (gitignored)
└── README.md
```

## Disclaimer

This tool is for educational reverse engineering purposes only. Using automated tools to create accounts may violate OpenAI's Terms of Service. Use at your own risk.
