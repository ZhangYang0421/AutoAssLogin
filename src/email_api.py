"""
邮箱验证码 API 封装。

通过第三方邮箱管理系统 API 获取最新邮件，
从中提取 ChatGPT 登录验证码（6 位数字）。
"""
import time
import logging
from typing import Optional
from curl_cffi import requests as cffi_requests

from .utils import extract_verification_code

logger = logging.getLogger(__name__)


class EmailAPI:
    """邮箱验证码获取器。"""

    def __init__(
        self,
        api_key: str,
        pt: str,
        base_url: str = "http://ms.outlook007.cc/api/open/email/latest",
        poll_interval: int = 5,
        poll_timeout: int = 120,
    ):
        """
        Args:
            api_key: 邮箱 API 的 api_key
            pt: 邮箱 API 的 pt 参数
            base_url: API 地址
            poll_interval: 轮询间隔（秒）
            poll_timeout: 最大等待时间（秒）
        """
        self.api_key = api_key
        self.pt = pt
        self.base_url = base_url
        self.poll_interval = poll_interval
        self.poll_timeout = poll_timeout

    def get_verification_code(self, email: str, pt: Optional[str] = None) -> Optional[str]:
        """
        轮询邮箱 API，获取指定邮箱的最新验证码邮件，
        提取 6 位数字验证码。

        Args:
            email: 目标邮箱地址
            pt: 可选，覆盖实例默认的 pt 参数（用于每个账号独立 pt 的场景）

        Returns:
            6 位验证码字符串，超时返回 None
        """
        logger.info(f"等待邮箱验证码: {email}（最长 {self.poll_timeout}s）")

        params = {
            "api_key": self.api_key,
            "pt": pt or self.pt,
            "email": email,
        }

        max_attempts = self.poll_timeout // self.poll_interval

        for attempt in range(max_attempts):
            try:
                resp = cffi_requests.get(self.base_url, params=params, timeout=10)
                data = resp.json()
            except Exception as e:
                logger.warning(f"邮箱 API 请求失败 (第 {attempt + 1} 次): {e}")
                time.sleep(self.poll_interval)
                continue

            if data.get("status") == "success":
                body = data.get("body", "")
                subject = data.get("subject", "")

                code = extract_verification_code(body, subject)
                if code:
                    logger.info(f"✓ 提取到验证码: {code}")
                    return code
                else:
                    logger.debug(f"邮件中未找到验证码，继续等待...")
            else:
                logger.debug(f"API 返回非成功状态: {data.get('status')}")

            time.sleep(self.poll_interval)

        logger.warning(f"✗ 获取验证码超时: {email}")
        return None
