"""
Token 持久化管理。

保存/加载 access_token 和 refresh_token 到 tokens/ 目录。
"""
import json
import logging
from pathlib import Path
from datetime import datetime, timezone

from .utils import sanitize_filename

logger = logging.getLogger(__name__)


class TokenManager:
    """Token 的保存和加载。"""

    def __init__(self, tokens_dir: str | Path = "./tokens"):
        self.tokens_dir = Path(tokens_dir)
        self.tokens_dir.mkdir(parents=True, exist_ok=True)

    def save(self, email: str, tokens: dict) -> Path:
        """
        保存 token 到文件。

        Args:
            email: 账号邮箱
            tokens: token 数据，应包含 access_token, refresh_token 等

        Returns:
            保存的文件路径
        """
        filename = f"{sanitize_filename(email)}_token.json"
        filepath = self.tokens_dir / filename

        data = {
            "email": email,
            "saved_at": datetime.now(timezone.utc).isoformat(),
            **tokens,
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info(f"Token 已保存: {filepath}")
        return filepath

    def load(self, email: str) -> dict | None:
        """
        加载已保存的 token。

        Returns:
            token 字典，文件不存在返回 None
        """
        filename = f"{sanitize_filename(email)}_token.json"
        filepath = self.tokens_dir / filename

        if not filepath.exists():
            return None

        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)

    def exists(self, email: str) -> bool:
        """检查 token 文件是否已存在。"""
        filename = f"{sanitize_filename(email)}_token.json"
        return (self.tokens_dir / filename).exists()
