# ChatGPT Auto Register

> 💬 交流群：**1060714372**
> 🍎 建议搭配 [heartmore/icloud-hme](https://github.com/heartmore/icloud-hme) 食用 — iCloud Hide My Email 纯协议管理工具

纯协议逆向实现的 ChatGPT 手机号全自动注册工具。无需浏览器，从获取号码到拿到 Session Token 端到端自动化。

基于 [heartmore/chatgpt-auto-register](https://github.com/heartmore/chatgpt-auto-register) 改进。

---

## 原理

三条独立技术组合为一条流水线：

| 层级 | 技术 | 绕过目标 |
|------|------|----------|
| 网络层 | `curl_cffi` Chrome TLS 指纹 | Cloudflare |
| 反爬层 | Sentinel FNV-1a 工作量证明 | auth.openai.com JS 挑战 |
| 接码层 | SMSBower / hero-sms / 5sim API | 短信验证码自动获取 |

注册流程共 9 步，全程 HTTP API 交互：

```
SMSBower              ChatGPT / OpenAI
─────────             ───────────────────
getNumber() ──┐
              ├── [01] GET  chatgpt.com/auth/login
              ├── [02] GET  /api/auth/csrf
              ├── [03] POST /api/auth/signin/openai
              ├── [04] GET  auth.openai.com/authorize (OAuth 重定向)
手机号 ───────┤
              ├── [05] POST /api/accounts/user/register
              ├── [06] GET  /api/accounts/phone-otp/send
wait_code() ◄─┤
收到验证码 ───┘
              ├── [07] POST /api/accounts/phone-otp/validate
              ├── [08] POST /api/accounts/create_account
              └── [09] GET  /api/auth/callback/openai → session_token
```

---

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置

```bash
cp config.example.json config.json
```

编辑 `config.json`，填写 SMSBower API Key：

```json
{
  "smsbower": { "api_key": "YOUR_KEY" },
  "proxy": "socks5h://127.0.0.1:10808",
  "country": "151",
  "service": "dr"
}
```

### 3. 运行

```bash
# Web GUI（推荐）
python web_gui.py
# 浏览器打开 http://127.0.0.1:8080

# 命令行
python auto_register.py                # 交互模式
python auto_register.py -n 3           # 注册 3 个号
python auto_register.py --country 33   # 指定国家
```

---

## Web GUI

`web_gui.py` 提供完整的 Web 控制台：

- 配置管理（API Key、代理、国家、价格上限）
- iCloud Cookies 一键导入
- 实时日志流（SSE）
- Phase 1 注册 + Phase 2 OAuth 绑邮箱上传全自动
- 结果下载

### iCloud 邮箱（可选）

如果配置了 SUB2API，注册完成后会自动：

1. 从 iCloud 创建/复用 Hide My Email 别名
2. OAuth 登录 → 绑定邮箱 → 验证码 → 同意授权
3. 上传 session_token 到 SUB2API

导入 iCloud Cookies：在 Web GUI 的 "iCloud Cookies 导入" 区域粘贴 JSON，或先运行：

```bash
python icloud_hme.py export-cookies
```

---

## 配置参考

| 键 | 默认值 | 说明 |
|----|--------|------|
| `smsbower.api_key` | (必填) | SMSBower API Key |
| `register.password` | 随机 | 账号密码 |
| `register.name` | 随机 | 昵称 |
| `register.birthdate` | 随机 | 生日 |
| `proxy` | 直连 | 代理，如 `socks5h://127.0.0.1:10808` |
| `country` | `151` | SMSBower 国家 ID |
| `service` | `dr` | 服务代码（`dr`=OpenAI） |
| `max_price` | 不限 | 号码最高单价 |
| `code_timeout` | `30` | 验证码等待秒数 |

### 已验证国家

| 国家 | ID | 参考价格 |
|------|----|---------|
| 智利 | `151` | ~$0.04 |
| 哥伦比亚 | `33` | ~$0.014 |
| 加拿大 | `36` | ~$0.031 |

更多国家可用 `smsbower.py` 查询。

---

## 项目结构

```
├── web_gui.py              # Web GUI (Flask + SSE)
├── auto_register.py        # CLI + register_one 引擎
├── chatgpt_register.py     # 核心：curl_cffi + Sentinel 协议引擎
├── smsbower.py             # SMSBower API 客户端
├── sentinel.py             # OpenAI Sentinel 反爬 PoW
│
├── openai_bind_email.py    # Phase 2: OAuth → 绑邮箱 → 验证 → 同意 → code
├── openai_oauth.py         # OAuth token 交换
├── openai_pipeline.py      # 全链路编排器
├── phone_sms.py            # SMSBower / hero-sms / 5sim 多平台接码
├── icloud_hme.py           # iCloud Hide My Email + cookies 导出
├── phase2_codex.py         # Phase 2 薄封装
├── test_pipeline.py        # 日常测试入口
│
├── config.example.json     # 配置模板
├── requirements.txt        # Python 依赖
└── README.md
```

---

## 相关项目

- [heartmore/icloud-hme](https://github.com/heartmore/icloud-hme) — iCloud Hide My Email 纯协议管理，一键导出 cookies，搭配本工具完成全链路注册

---

## 致谢

- [heartmore/chatgpt-auto-register](https://github.com/heartmore/chatgpt-auto-register) — 原始协议逆向实现
- [open-reg-auto](https://github.com/wuchenwl/open-reg-auto) — Sentinel 工作量证明方案

---

## 声明

本项目仅供逆向工程学习和研究使用。使用自动化工具创建账号可能违反 OpenAI 服务条款，请自行承担风险。
