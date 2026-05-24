"""
AutoFreeLogin 共享工具模块
提供账号加载、路径管理、凭据持久化、邮箱轮询、浏览器工厂、WebAuthn 助手等功能。
"""
import sys
import json
import time
import re
import hashlib
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import argparse

# ============================================================
# 常量
# ============================================================

TOKENS_DIR = Path("./tokens")
BROWSER_DATA_DIR = Path("./browser_data")

# ============================================================
# 2.1 账号加载
# ============================================================

def load_account(filepath, index=0):
    """从 JSONL 文件读取第 index 行账号（0-based）"""
    with open(filepath, "r", encoding="utf-8-sig") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            if i == index:
                return json.loads(line)
    return None


def parse_mailbox_params(mailbox_url):
    """解析 mailbox URL 提取 api_key、pt 和 base URL"""
    parsed = urlparse(mailbox_url)
    params = parse_qs(parsed.query)
    return {
        "pt": params.get("pt", [None])[0],
        "api_key": params.get("api_key", [None])[0],
        "base": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
    }


def generate_uid(email):
    """生成 8 位 uid（md5 前 8 位）"""
    return hashlib.md5(email.encode()).hexdigest()[:8]


# ============================================================
# 2.2 路径管理
# ============================================================

class Paths:
    """统一管理 tokens 和 browser_data 路径"""

    def __init__(self, uid, email):
        self.uid = uid
        self.email = email

    # --- 目录 ---
    @property
    def tokens_dir(self):
        return TOKENS_DIR

    @property
    def browser_data_dir(self):
        return BROWSER_DATA_DIR

    @property
    def uid_tokens_dir(self):
        return TOKENS_DIR / self.uid

    @property
    def token_dir(self):
        return TOKENS_DIR / "token"

    @property
    def browser_profile_dir(self):
        return BROWSER_DATA_DIR / self.uid

    # --- 文件 ---
    def passkey_file(self, index):
        return self.uid_tokens_dir / f"passkey_{index}.json"

    def recovery_keys_file(self):
        return self.uid_tokens_dir / "recovery_keys.txt"

    def token_file(self):
        return self.token_dir / f"{self.email}_token.json"

    # --- 初始化 ---
    def ensure_dirs(self):
        """创建所需目录"""
        self.uid_tokens_dir.mkdir(parents=True, exist_ok=True)
        self.token_dir.mkdir(parents=True, exist_ok=True)
        self.browser_profile_dir.mkdir(parents=True, exist_ok=True)


# ============================================================
# 2.3 凭据持久化
# ============================================================

def save_passkey_credential(uid, cred_data, index):
    """保存捕获的 passkey 凭据到磁盘"""
    TOKENS_DIR.mkdir(parents=True, exist_ok=True)
    cred_file = TOKENS_DIR / uid / f"passkey_{index}.json"
    cred_file.parent.mkdir(parents=True, exist_ok=True)
    cred_file.write_text(json.dumps(cred_data, indent=2), encoding="utf-8")
    print(f"  [SAVED] {cred_file}")
    return cred_file


def load_passkey_credentials(uid):
    """加载所有已保存的 passkey 凭据，返回 list[dict]"""
    credentials = []
    uid_dir = TOKENS_DIR / uid
    if not uid_dir.exists():
        return credentials
    for f in sorted(uid_dir.glob("passkey_*.json")):
        try:
            credentials.append(json.loads(f.read_text(encoding="utf-8")))
        except Exception:
            pass
    return credentials


def save_recovery_keys(uid, email, keys):
    """保存恢复密钥到 tokens/{uid}/recovery_keys.txt"""
    key_file = TOKENS_DIR / uid / "recovery_keys.txt"
    key_file.parent.mkdir(parents=True, exist_ok=True)
    with open(key_file, "w", encoding="utf-8") as f:
        f.write(f"Recovery keys for {email}\n")
        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for i, k in enumerate(keys, 1):
            f.write(f"{i}. {k}\n")
    print(f"  [SAVED] 恢复密钥 ({len(keys)} 个): {key_file}")
    return key_file


def save_session_token(email, session_data):
    """保存 session token 到 tokens/token/{email}_token.json"""
    token_path = TOKENS_DIR / "token" / f"{email}_token.json"
    token_path.parent.mkdir(parents=True, exist_ok=True)
    token_path.write_text(json.dumps(session_data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"  [SAVED] Token: {token_path}")
    return token_path


# ============================================================
# 2.4 邮箱轮询
# ============================================================

class EmailPoller:
    """邮箱验证码轮询器，支持基线对比和新邮件检测"""

    def __init__(self, mail_params, proxies=None):
        """
        mail_params: {"base": str, "api_key": str, "pt": str, "email": str}
        proxies: {"http": str, "https": str} | None
        """
        import requests as req
        self.req = req
        self.base = mail_params["base"]
        self.query = {
            "api_key": mail_params["api_key"],
            "pt": mail_params["pt"],
            "email": mail_params["email"],
        }
        self.proxies = proxies

    def get_latest(self):
        """获取最新邮件，返回 (code, received_at) 或 (None, None)"""
        try:
            resp = self.req.get(self.base, params=self.query,
                               proxies=self.proxies, timeout=15)
            data = resp.json()
            return data.get("code", ""), data.get("received_at", "")
        except Exception:
            return None, None

    def wait_for_code(self, timeout=600, interval=5,
                      baseline_code=None, baseline_time=None,
                      resend_callback=None):
        """
        轮询等待新验证码。

        timeout: 最大等待秒数
        interval: 轮询间隔秒数
        baseline_code: 基线验证码（用于检测新码）
        baseline_time: 基线时间（用于检测新邮件）
        resend_callback: 每 2 分钟触发一次的回调（用于点击"重新发送"）

        返回: 新验证码字符串 或 None（超时）
        """
        iterations = timeout // interval
        for i in range(iterations):
            code, recv = self.get_latest()

            # 检查是否是新邮件
            is_new = False
            if recv and baseline_time and recv != baseline_time:
                is_new = True
            if code and baseline_code and code != baseline_code:
                is_new = True

            if is_new and code and len(str(code)) >= 4:
                elapsed = i * interval
                print(f"\n  *** 验证码: {code} (第{i+1}次轮询, {elapsed}s) ***")
                return code

            # 每 2 分钟触发 resend callback
            if resend_callback and i > 0 and i % (120 // interval) == 0:
                resend_callback()

            if i % 12 == 0 and i > 0:
                print(f"    等待中... {i * interval}s")

            time.sleep(interval)

        return None


# ============================================================
# 2.5 Playwright 浏览器工厂
# ============================================================

def create_browser_context(pw, uid, proxy=None, headless=True):
    """
    创建持久化浏览器上下文，返回 (context, page)。

    pw: sync_playwright() 实例
    uid: 用户 ID（用于 browser_data 目录隔离）
    proxy: 代理 URL 字符串
    headless: 无头模式
    """
    user_data_dir = str((BROWSER_DATA_DIR / uid).resolve())

    ctx = pw.chromium.launch_persistent_context(
        user_data_dir=user_data_dir,
        headless=headless,
        proxy={"server": proxy} if proxy else None,
        viewport={"width": 1280, "height": 900},
        locale="zh-CN",
        args=["--disable-blink-features=AutomationControlled", "--no-sandbox"],
    )
    ctx.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', { get: () => false });
        window.chrome = { runtime: {} };
    """)
    page = ctx.new_page()
    return ctx, page


# ============================================================
# 2.6 CDP WebAuthn 助手
# ============================================================

def setup_webauthn(page):
    """
    启用 WebAuthn CDP 域，返回 CDPSession。
    """
    cdp = page.context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    return cdp


def add_virtual_authenticator(cdp, transport="internal"):
    """
    添加虚拟认证器，返回 (authenticatorId, transport)。

    transport: 'internal' | 'usb' | 'nfc' | 'ble'
    """
    result = cdp.send("WebAuthn.addVirtualAuthenticator", {
        "options": {
            "protocol": "ctap2",
            "transport": transport,
            "hasUserVerification": True,
            "isUserVerified": True,
            "hasResidentKey": True,
            "automaticPresenceSimulation": True,
        }
    })
    auth_id = result.get("authenticatorId", "")
    print(f"  [WebAuthn] 认证器: {auth_id[:20]}... [{transport}]")
    return auth_id


def import_credential(cdp, auth_id, credential):
    """
    导入 passkey 凭据到虚拟认证器。
    """
    cdp.send("WebAuthn.addCredential", {
        "authenticatorId": auth_id,
        "credential": credential,
    })


# ============================================================
# 2.7 Token 提取
# ============================================================

def extract_session_token(page):
    """
    导航到 /api/auth/session，提取 session token。

    返回: dict | None
    """
    try:
        page.goto("https://chatgpt.com/api/auth/session", timeout=15000)
        raw = page.content()
        # 提取 body 内容
        m = re.search(r"<body[^>]*>(.*?)</body>", raw, re.DOTALL)
        text = m.group(1) if m else raw
        text = re.sub(r"<[^>]+>", "", text).strip()
        session = json.loads(text)
        if session.get("accessToken"):
            return session
    except Exception:
        pass
    return None


# ============================================================
# 2.8 UI 交互助手
# ============================================================

def fill_input(page, selectors, value):
    """
    尝试多个选择器填值，返回是否成功。

    selectors: CSS 选择器列表（按优先级尝试）
    """
    for sel in selectors:
        try:
            el = page.wait_for_selector(sel, timeout=3000)
            if el and el.is_visible():
                el.fill(value)
                return True
        except Exception:
            continue
    return False


def click_button(page, selectors, timeout=3000):
    """
    尝试多个选择器点击按钮，返回是否成功。

    selectors: CSS 选择器列表（按优先级尝试）
    """
    for sel in selectors:
        try:
            btn = page.wait_for_selector(sel, timeout=timeout)
            if btn and btn.is_visible() and btn.is_enabled():
                label = btn.inner_text().strip()[:40]
                print(f"  点击: {label}")
                btn.click()
                return True
        except Exception:
            continue
    return False


def wait_for_continue_enabled(page, label="继续", max_wait=15):
    """
    等待"继续"按钮启用（aria-disabled 变为 false），然后点击。

    返回: 是否成功点击
    """
    for i in range(max_wait):
        time.sleep(1)
        aria = page.evaluate(f"""() => {{
            const btns = document.querySelectorAll('button');
            for (const b of btns) {{
                if (b.innerText.includes('{label}'))
                    return b.getAttribute('aria-disabled');
            }}
            return 'not found';
        }}""")
        if aria == "false" or aria is None:
            try:
                page.click(f'button:has-text("{label}")')
                print(f"  点击: {label}")
                time.sleep(5)
                return True
            except Exception:
                pass
            break
    return False


# ============================================================
# 2.9 CLI 参数
# ============================================================

def create_cli_parser(description=""):
    """创建统一的 CLI 参数解析器"""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--account", default="1.txt",
                        help="账号文件路径（JSONL 格式）")
    parser.add_argument("--index", type=int, default=0,
                        help="账号文件中的行索引（0-based）")
    parser.add_argument("--proxy", default="http://127.0.0.1:7890",
                        help="HTTP 代理地址")
    parser.add_argument("--debug", action="store_true",
                        help="启用调试模式（保存截图）")
    parser.add_argument("--visible", action="store_true",
                        help="显示浏览器窗口（非 headless）")
    return parser


# ============================================================
# 调试截图辅助
# ============================================================

def screenshot(page, uid, name, debug=False):
    """调试模式下保存截图"""
    if debug:
        path = f"debug_{uid}_{name}.png"
        page.screenshot(path=path)
        print(f"  [DEBUG] 截图: {path}")
