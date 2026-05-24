"""
curl_cffi HTTP 客户端封装。

模拟 Chrome 120 TLS 指纹，绕过 Cloudflare 等 WAF 检测。
支持代理配置和 Session 管理。
"""
import logging
from typing import Optional
from curl_cffi import requests as cffi_requests
from curl_cffi.requests import Response

logger = logging.getLogger(__name__)

# Chrome 120 的默认请求头
DEFAULT_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
}


class HTTPClient:
    """基于 curl_cffi 的 HTTP 客户端，模拟 Chrome 浏览器。"""

    def __init__(
        self,
        proxy: Optional[str] = None,
        impersonate: str = "chrome124",
        timeout: int = 30,
    ):
        """
        Args:
            proxy: 代理 URL，如 http://user:pass@host:port，为 None 则不使用代理
            impersonate: curl_cffi 指纹模拟目标
            timeout: 请求超时秒数
        """
        self.session = cffi_requests.Session()
        self.session.impersonate = impersonate
        self.session.timeout = timeout
        self.session.headers.update(DEFAULT_HEADERS)

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
            logger.info(f"使用代理: {proxy}")
        else:
            logger.info("不使用代理，走本机 IP")

    def get(
        self,
        url: str,
        headers: Optional[dict] = None,
        allow_redirects: bool = True,
        **kwargs,
    ) -> Response:
        """发送 GET 请求。"""
        logger.debug(f"GET {url}")
        resp = self.session.get(
            url,
            headers=headers,
            allow_redirects=allow_redirects,
            **kwargs,
        )
        logger.debug(f"  ← {resp.status_code} | {resp.url}")
        return resp

    def post(
        self,
        url: str,
        data: Optional[dict] = None,
        json: Optional[dict] = None,
        headers: Optional[dict] = None,
        allow_redirects: bool = True,
        **kwargs,
    ) -> Response:
        """发送 POST 请求。"""
        logger.debug(f"POST {url}")
        resp = self.session.post(
            url,
            data=data,
            json=json,
            headers=headers,
            allow_redirects=allow_redirects,
            **kwargs,
        )
        logger.debug(f"  ← {resp.status_code} | {resp.url}")
        return resp

    def reset_session(self):
        """重置 Session（清空 cookies 和 headers 回默认）。"""
        self.session = cffi_requests.Session()
        self.session.impersonate = "chrome120"
        self.session.timeout = 30
        self.session.headers.update(DEFAULT_HEADERS)
