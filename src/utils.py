"""
工具函数：PKCE 生成、验证码提取、URL 解析等。
"""
import random
import string
import hashlib
import base64
import re
import json
import yaml
from pathlib import Path
from typing import Optional


def generate_code_verifier(length: int = 64) -> str:
    """
    生成 PKCE code_verifier。

    RFC 7636 规范：43-128 字符的随机字符串，
    仅包含 A-Z a-z 0-9 - . _ ~
    """
    charset = string.ascii_letters + string.digits + "-._~"
    return "".join(random.choice(charset) for _ in range(length))


def generate_code_challenge(code_verifier: str) -> str:
    """
    根据 code_verifier 生成 PKCE code_challenge (S256 方式)。

    code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
    """
    sha256 = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(sha256).rstrip(b"=").decode("ascii")


def extract_verification_code(body: str, subject: str = "") -> Optional[str]:
    """
    从邮件正文中提取 6 位数字验证码。

    优先匹配 "code"/"verification" 关键词附近的 6 位数字，
    回退匹配任意独立的 6 位数字。

    返回 None 表示未找到。
    """
    if not body:
        return None

    text = f"{subject}\n{body}"

    # 优先级 1: "code: XXXXXX" 或 "code\nXXXXXX" 模式
    match = re.search(r"code[:\s]+(\d{6})", text, re.IGNORECASE)
    if match:
        return match.group(1)

    # 优先级 2: "verification code" 附近的 6 位数字
    match = re.search(r"verification\s*code[:\s]*(\d{6})", text, re.IGNORECASE)
    if match:
        return match.group(1)

    # 优先级 3: 独立的 6 位数字（排除年份、连续相同数字等噪音）
    matches = re.findall(r"\b(\d{6})\b", text)
    for m in matches:
        # 过滤掉明显不是验证码的：如 202020, 111111 可能是噪音
        # 但暂时保留，让用户验证
        return m

    return None


def load_json(path: str | Path) -> dict | list:
    """加载 JSON 文件。"""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_yaml(path: str | Path) -> dict:
    """加载 YAML 配置文件。"""
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_accounts(path: str | Path) -> list[dict]:
    """
    加载账号列表。

    支持格式：
    - JSON 数组: [{"email": "...", "password": "..."}]
    - JSONL: 每行一个 JSON 对象（如 1.txt 格式），自动提取 email/password/mail_pt
    """
    path = Path(path)
    with open(path, "r", encoding="utf-8-sig") as f:
        first_char = f.read(1)
        f.seek(0)

        if first_char == "[":
            # JSON 数组格式
            data = json.load(f)
            if not isinstance(data, list):
                raise ValueError(f"accounts 文件应为 JSON 数组，实际类型: {type(data)}")
            return data
        else:
            # JSONL 格式 — 每行一个 JSON 对象
            return load_accounts_jsonl(f)


def load_accounts_jsonl(fileobj) -> list[dict]:
    """
    从 JSONL 文件对象加载账号列表。

    自动提取 email, password, mail_pt 字段。
    支持 1.txt 格式（含 mailbox_url / mailbox_connection）。
    """
    from urllib.parse import urlparse, parse_qs

    accounts = []
    for line in fileobj:
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)

        email = obj.get("email", "")
        password = obj.get("password", "")

        # 从 mailbox_url / mailbox_connection 提取 pt 和 api_key
        mailbox_url = obj.get("mailbox_url", "") or obj.get("mailbox_connection", "")
        parsed = urlparse(mailbox_url)
        params = parse_qs(parsed.query)
        mail_pt = params.get("pt", [None])[0]
        mail_api_key = params.get("api_key", [None])[0]

        accounts.append({
            "email": email,
            "password": password,
            "mail_pt": mail_pt,
            "mail_api_key": mail_api_key,
            # 保留原始数据中的有用字段
            "refresh_token": obj.get("refresh_token", ""),
            "access_token": obj.get("access_token", ""),
            "client_id": obj.get("client_id", ""),
        })

    return accounts


def sanitize_filename(email: str) -> str:
    """将 email 转为安全的文件名。"""
    return email.replace("@", "_at_").replace(".", "_")
