# AutoFreeLogin

ChatGPT 自动登录工具集，支持密码登录、Passkey 免密登录、AAS（Advanced Account Security）注册。

## 项目结构

```
AutoFreeLogin/
├── common.py               # 共享工具模块（浏览器工厂、邮箱轮询、WebAuthn 助手等）
├── aas_enroll.py            # 模块1: 完整 AAS 注册（登录→注册 Passkey→持久化凭据）
├── login_passkey.py         # 模块2: Passkey 凭据登录（CDP 导入凭据→认证→获取 Token）
├── login_password.py        # 模块3: 密码+OTP 登录（邮箱→密码→验证码→Token）
├── src/                     # 协议登录方案（纯 HTTP，无需浏览器）
├── config.example.yaml      # 配置文件示例
├── account.example.jsonl    # 账号文件格式示例
└── requirements.txt         # Python 依赖
```

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
playwright install chromium
```

### 2. 准备配置文件

```bash
# 复制示例配置并填入真实值
cp config.example.yaml config.yaml
```

`config.yaml` 中需要填写：
- `email_api.base_url` — 邮箱 API 地址（用于接收验证码）
- `email_api.api_key` / `email_api.pt` — 邮箱 API 认证参数
- `proxy` — HTTP 代理地址（如 `http://127.0.0.1:7890`）

### 3. 准备账号文件

账号文件为 **JSONL 格式**（每行一个 JSON 对象），至少包含以下字段：

```jsonl
{"email": "user@example.com", "password": "password123", "mailbox_url": "http://mail-api.com/latest?api_key=KEY&pt=TOKEN&email=user@example.com"}
```

参考 `account.example.jsonl`。

### 4. 选择登录方式

```bash
# 方式一：密码+OTP 登录（最简单，无需 AAS）
python login_password.py --account 3.txt --index 0 --visible

# 方式二：Passkey 登录（需先完成 AAS 注册）
python login_passkey.py --account 1.txt --index 0 --visible

# 方式三：完整 AAS 注册（登录→注册 Passkey→获取恢复密钥）
python aas_enroll.py --account 1.txt --index 0 --visible
```

## 三个模块详解

### 模块1: `aas_enroll.py` — 完整 AAS 注册

**流程（6步）：**
1. 邮箱 + 密码/OTP 登录
2. 导航到 AAS 页面，点击"加入"
3. 重新认证（密码/OTP）+ 邮箱验证码确认
4. 注册 2 个 Passkey（CDP `credentialAdded` 事件捕获私钥）
5. 提取并保存恢复密钥
6. 最终确认，提取 session token

**输出文件：**
- `tokens/{uid}/passkey_1.json` — Passkey 凭据 1（私钥）
- `tokens/{uid}/passkey_2.json` — Passkey 凭据 2
- `tokens/{uid}/recovery_keys.txt` — 恢复密钥
- `tokens/token/{email}_token.json` — Session Token

### 模块2: `login_passkey.py` — Passkey 登录

**前置条件：** 已完成 AAS 注册（存在 `tokens/{uid}/passkey_*.json`）

**流程：**
1. 加载已保存的 passkey 凭据
2. 为每个凭据创建 CDP 虚拟认证器（transport: internal/usb/nfc/ble）
3. `addCredential` 导入凭据
4. 导航登录页 → 填邮箱 → 遇到 passkey 挑战自动完成认证
5. 提取 session token

### 模块3: `login_password.py` — 密码+OTP 登录

**流程：**
1. 导航登录页 → 填邮箱
2. 密码页 → 填密码
3. 邮箱验证页 → 自动轮询验证码 → 填入 → 提交
4. 提取 session token

> 如果遇到 passkey 挑战，说明账号已启用 AAS，请改用 `login_passkey.py`。

## 共享模块 `common.py`

所有模块共享的工具函数：

| 模块 | 功能 |
|------|------|
| `load_account()` / `parse_mailbox_params()` / `generate_uid()` | 账号加载与解析 |
| `Paths` 类 | 统一路径管理（tokens、browser_data） |
| `save_passkey_credential()` / `load_passkey_credentials()` | Passkey 凭据持久化 |
| `save_recovery_keys()` / `save_session_token()` | 恢复密钥 / Token 保存 |
| `EmailPoller` 类 | 邮箱验证码轮询（基线对比、自动重发） |
| `create_browser_context()` | Playwright 持久化浏览器工厂 |
| `setup_webauthn()` / `add_virtual_authenticator()` / `import_credential()` | CDP WebAuthn 助手 |
| `extract_session_token()` | 从 `/api/auth/session` 提取 Token |
| `fill_input()` / `click_button()` / `wait_for_continue_enabled()` | UI 交互助手 |
| `create_cli_parser()` | 统一 CLI 参数解析器 |

## CLI 参数

所有模块支持统一的命令行参数：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--account` | `1.txt` | 账号文件路径（JSONL 格式） |
| `--index` | `0` | 账号文件中的行索引（0-based） |
| `--proxy` | `http://127.0.0.1:7890` | HTTP 代理地址 |
| `--visible` | `false` | 显示浏览器窗口（调试用） |
| `--debug` | `false` | 启用调试截图 |

## 输出目录

```
tokens/
├── {uid}/                   # uid = md5(email)[:8]
│   ├── passkey_1.json       # Passkey 凭据（含私钥）
│   ├── passkey_2.json
│   └── recovery_keys.txt    # AAS 恢复密钥
└── token/
    └── {email}_token.json   # Session Token（accessToken + user + expires）

browser_data/
└── {uid}/                   # Playwright 持久化浏览器上下文
```

## 环境要求

- **Python** ≥ 3.9
- **Playwright** ≥ 1.40（Chromium 浏览器）
- **操作系统**：Windows / macOS / Linux
- **代理**：需要 HTTP 代理访问 ChatGPT

## 安全提醒

- `config.yaml`、账号文件（`*.txt`）、`tokens/`、`browser_data/` 已加入 `.gitignore`，**不会被提交到 Git**
- Passkey 私钥存储在 `tokens/{uid}/` 中，请妥善保管
- 恢复密钥保存在本地文件，建议另外备份到安全位置
