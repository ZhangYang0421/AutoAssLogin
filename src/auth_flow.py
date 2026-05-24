"""
ChatGPT OAuth2 PKCE 登录流程。

参考 codex_register 项目的逆向分析，实现完整的 Auth0 登录流程：
  1. GET  /auth/login                    → 建立 Session，获取 CSRF cookie
  2. GET  /api/auth/session              → 确认未登录状态
  3. POST /api/auth/signin/auth0         → 获取 Auth0 授权重定向 URL
  4. GET  auth0 /authorize               → 获取登录表单页面和 state token
  5. POST auth0 /u/login/identifier      → 提交邮箱
  6. POST auth0 /u/login/password        → 提交密码
  7. [条件] POST /u/mfa-email-challenge  → 邮箱验证码验证
  8. 跟随 OAuth callback                 → 拿 authorization code
  9. POST /oauth/token                   → code_verifier + code → tokens
"""
import re
import logging
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from curl_cffi.requests import Response

from .http_client import HTTPClient
from .email_api import EmailAPI
from .utils import generate_code_verifier, generate_code_challenge

logger = logging.getLogger(__name__)

# ChatGPT 常量
CHATGPT_BASE = "https://chatgpt.com"
AUTH0_BASE = "https://auth0.openai.com"
AUTH0_OAUTH_TOKEN_URL = "https://auth.openai.com/oauth/token"

# Auth0 客户端 ID（ChatGPT Web 应用），会从 authorize URL 动态提取，此作为 fallback
FALLBACK_CLIENT_ID = "DRivsnm2Mu42T3KOpqdtwB3NYviHYwzWGp8HjoA0pDF"
FALLBACK_REDIRECT_URI = "https://chatgpt.com/api/auth/callback/auth0"


class AuthFlowError(Exception):
    """认证流程错误。"""
    pass


class MFAREquired(Exception):
    """需要邮箱验证码（MFA）。"""

    def __init__(self, state: str):
        self.state = state
        super().__init__(f"MFA required, state={state}")


class LoginResult:
    """登录结果。"""

    def __init__(self, success: bool, tokens: Optional[dict] = None, error: Optional[str] = None):
        self.success = success
        self.tokens = tokens or {}
        self.error = error


class ChatGPTAuth:
    """ChatGPT OAuth2 PKCE 登录器。"""

    def __init__(self, http_client: HTTPClient, email_api: EmailAPI):
        self.client = http_client
        self.email_api = email_api
        # 在 login() 中设置
        self.code_verifier: str = ""
        self.code_challenge: str = ""
        self.client_id: str = ""
        self.redirect_uri: str = ""

    # ── 公开方法 ─────────────────────────────────────────────

    def login(self, email: str, password: str, mail_pt: Optional[str] = None) -> LoginResult:
        """
        执行完整的 ChatGPT 登录流程。

        Args:
            email: 账号邮箱
            password: 账号密码
            mail_pt: 可选，邮箱 API 的 pt 参数（覆盖 email_api 默认值）

        Returns:
            LoginResult，包含 tokens 或错误信息
        """
        # 保存 pt 供后续使用
        self._mail_pt = mail_pt
        # 生成 PKCE 参数
        self.code_verifier = generate_code_verifier()
        self.code_challenge = generate_code_challenge(self.code_verifier)
        logger.info(f"PKCE code_verifier 长度: {len(self.code_verifier)}")

        try:
            # Step 1–3: 建立会话并获取 Auth0 授权 URL
            auth0_url = self._initiate_auth()

            # Step 4: 访问 Auth0 授权页，提取 transaction state
            tx_state = self._load_auth0_authorize(auth0_url)

            # Step 5: 提交邮箱
            tx_state, needs_mfa = self._submit_identifier(email, tx_state)

            # Step 6: 提交密码
            tx_state, needs_mfa = self._submit_password(email, password, tx_state)

            # Step 7: 处理 MFA（邮箱验证码）
            if needs_mfa:
                tx_state = self._handle_mfa(email, tx_state)

            # Step 8: 跟随 OAuth 回调，获取 authorization code
            auth_code = self._follow_callback(tx_state)

            # Step 9: 用 code 换 token
            tokens = self._exchange_code_for_tokens(auth_code)

            logger.info(f"✓ 登录成功: {email}")
            return LoginResult(success=True, tokens=tokens)

        except AuthFlowError as e:
            logger.error(f"✗ 登录失败 [{email}]: {e}")
            return LoginResult(success=False, error=str(e))
        except Exception as e:
            logger.exception(f"✗ 未预期的错误 [{email}]: {e}")
            return LoginResult(success=False, error=str(e))

    # ── Step 1–3: 建立会话 ───────────────────────────────────

    def _initiate_auth(self) -> str:
        """
        Step 1: GET /auth/login → 建立 Session，获取 CSRF cookie
        Step 2: GET /api/auth/session → 确认未登录
        Step 3: POST /api/auth/signin/auth0?prompt=login → 获取 Auth0 授权 URL

        Returns:
            Auth0 authorize URL（已注入 PKCE 参数）
        """
        # Step 1
        logger.info("Step 1: 获取 CSRF cookie...")
        resp = self.client.get(f"{CHATGPT_BASE}/auth/login")
        if resp.status_code not in (200, 302, 303, 307, 308):
            raise AuthFlowError(f"Step 1 失败: HTTP {resp.status_code}")

        # Step 2
        logger.info("Step 2: 检查会话状态...")
        resp = self.client.get(
            f"{CHATGPT_BASE}/api/auth/session",
            headers={"Accept": "application/json"},
        )
        try:
            session_data = resp.json()
            if session_data and session_data.get("user"):
                raise AuthFlowError("当前已有登录态，请先登出或使用不同 Session")
        except Exception:
            pass  # 解析失败说明未登录，继续

        # Step 3
        logger.info("Step 3: 获取 Auth0 授权 URL...")
        resp = self.client.post(
            f"{CHATGPT_BASE}/api/auth/signin/auth0?prompt=login",
            json={"callbackUrl": "/"},
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )

        # 尝试解析 JSON 响应
        auth0_url = None
        try:
            data = resp.json()
            auth0_url = data.get("url")
        except Exception:
            pass

        # 如果不是 JSON，可能是直接重定向
        if not auth0_url:
            if resp.status_code in (302, 303, 307, 308):
                auth0_url = resp.headers.get("Location", "")
            elif "auth0.openai.com/authorize" in resp.text:
                match = re.search(r'https?://auth0\.openai\.com/authorize[^\s"\'<>]+', resp.text)
                if match:
                    auth0_url = match.group(0)

        if not auth0_url:
            raise AuthFlowError(
                f"Step 3 失败: 无法获取 Auth0 授权 URL (HTTP {resp.status_code})"
            )

        # 注入 PKCE 参数
        auth0_url = self._inject_pkce(auth0_url)
        logger.info(f"  授权 URL 已注入 PKCE 参数")

        return auth0_url

    # ── Step 4: 加载 Auth0 授权页 ─────────────────────────────

    def _load_auth0_authorize(self, auth0_url: str) -> str:
        """
        GET Auth0 /authorize → 解析 HTML，提取：
        - client_id, redirect_uri（保存到 self）
        - transaction state（用于后续表单提交）

        Returns:
            transaction state 字符串
        """
        logger.info("Step 4: 加载 Auth0 授权页...")
        resp = self.client.get(auth0_url)

        html = resp.text

        # 提取 client_id 和 redirect_uri
        self._extract_oauth_params(auth0_url, html)

        # 提取 transaction state
        tx_state = self._extract_transaction_state(html)
        if not tx_state:
            raise AuthFlowError("Step 4 失败: 无法从 Auth0 页面提取 transaction state")

        logger.info(f"  transaction state: {tx_state[:20]}...")
        return tx_state

    def _extract_oauth_params(self, auth0_url: str, html: str):
        """从 URL 和 HTML 中提取 client_id 和 redirect_uri。"""
        parsed = urlparse(auth0_url)
        params = parse_qs(parsed.query)

        self.client_id = params.get("client_id", [None])[0] or ""
        self.redirect_uri = params.get("redirect_uri", [None])[0] or ""

        # 如果 URL 中没有，尝试从 HTML 中提取
        if not self.client_id:
            match = re.search(r'client_id["\s:=]+["\']?([a-zA-Z0-9_-]+)', html)
            if match:
                self.client_id = match.group(1)

        if not self.redirect_uri:
            match = re.search(r'redirect_uri["\s:=]+["\']?(https?://[^"\'\s]+)', html)
            if match:
                self.redirect_uri = match.group(1)

        # Fallback
        if not self.client_id:
            self.client_id = FALLBACK_CLIENT_ID
        if not self.redirect_uri:
            self.redirect_uri = FALLBACK_REDIRECT_URI

        logger.debug(f"  client_id: {self.client_id}")
        logger.debug(f"  redirect_uri: {self.redirect_uri}")

    def _extract_transaction_state(self, html: str) -> Optional[str]:
        """从 Auth0 HTML 页面中提取 transaction state。"""
        # 尝试多种模式
        patterns = [
            # 表单 action 中的 state
            r'action=["\']/[^"\']*\?state=([a-zA-Z0-9_-]+)',
            # JavaScript 对象中的 state
            r'state["\s:]+["\']([a-zA-Z0-9_-]+)["\']',
            # URL 参数中的 state
            r'[?&]state=([a-zA-Z0-9_-]+)',
            # 隐藏 input 中的 state
            r'name=["\']state["\']\s+value=["\']([a-zA-Z0-9_-]+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, html)
            if match:
                return match.group(1)

        return None

    # ── Step 5: 提交邮箱 ─────────────────────────────────────

    def _submit_identifier(self, email: str, tx_state: str) -> tuple[str, bool]:
        """
        POST /u/login/identifier?state={tx_state}

        Returns:
            (new_state, needs_mfa): 新的 transaction state 和是否需要 MFA
        """
        logger.info(f"Step 5: 提交邮箱 {email}...")

        url = f"{AUTH0_BASE}/u/login/identifier?state={tx_state}"
        data = {
            "state": tx_state,
            "username": email,
            "js-available": "true",
            "webauthn-available": "true",
            "is-brave": "false",
            "webauthn-platform-available": "false",
            "action": "default",
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": AUTH0_BASE,
            "Referer": f"{AUTH0_BASE}/authorize?state={tx_state}",
        }

        resp = self.client.post(url, data=data, headers=headers, allow_redirects=False)

        return self._handle_auth0_response(resp, "Step 5")

    # ── Step 6: 提交密码 ─────────────────────────────────────

    def _submit_password(self, email: str, password: str, tx_state: str) -> tuple[str, bool]:
        """
        POST /u/login/password?state={tx_state}

        Returns:
            (new_state_or_code, needs_mfa)
        """
        logger.info("Step 6: 提交密码...")

        url = f"{AUTH0_BASE}/u/login/password?state={tx_state}"
        data = {
            "state": tx_state,
            "username": email,
            "password": password,
            "action": "default",
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": AUTH0_BASE,
            "Referer": f"{AUTH0_BASE}/u/login/password?state={tx_state}",
        }

        resp = self.client.post(url, data=data, headers=headers, allow_redirects=False)

        return self._handle_auth0_response(resp, "Step 6")

    # ── Step 7: 处理 MFA ─────────────────────────────────────

    def _handle_mfa(self, email: str, tx_state: str) -> str:
        """
        等待邮箱验证码，提交 MFA email challenge。

        Returns:
            新的 transaction state（指向 authorize/resume）
        """
        logger.info("Step 7: 处理邮箱验证码...")

        # 等待验证码（使用账号专属 pt 如果有）
        code = self.email_api.get_verification_code(email, pt=getattr(self, '_mail_pt', None))
        if not code:
            raise AuthFlowError(f"MFA 验证码获取超时: {email}")

        # 提交验证码
        logger.info(f"  提交验证码: {code}")
        url = f"{AUTH0_BASE}/u/mfa-email-challenge?state={tx_state}"
        data = {
            "state": tx_state,
            "code": code,
            "action": "default",
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": AUTH0_BASE,
            "Referer": f"{AUTH0_BASE}/u/mfa-email-challenge?state={tx_state}",
        }

        resp = self.client.post(url, data=data, headers=headers, allow_redirects=False)
        new_state, _ = self._handle_auth0_response(resp, "Step 7 (MFA)")

        return new_state

    # ── Step 8: 跟随 OAuth 回调 ──────────────────────────────

    def _follow_callback(self, tx_state: str) -> str:
        """
        跟随 authorize/resume → OAuth callback，提取 authorization code。

        Returns:
            authorization code 字符串
        """
        logger.info("Step 8: 跟随 OAuth 回调...")

        # 首先调用 /authorize/resume 完成 Auth0 侧的登录
        resume_url = f"{AUTH0_BASE}/authorize/resume?state={tx_state}"
        resp = self.client.get(resume_url, allow_redirects=False)

        if resp.status_code in (302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            # 提取 authorization code
            code = self._extract_code_from_url(location)
            if code:
                logger.info(f"  获取到 authorization code: {code[:20]}...")
                return code

            # 如果 Location 仍在 Auth0，继续跟随
            if "auth0.openai.com" in location:
                resp2 = self.client.get(
                    location if location.startswith("http") else f"{AUTH0_BASE}{location}",
                    allow_redirects=False,
                )
                if resp2.status_code in (302, 303, 307, 308):
                    location2 = resp2.headers.get("Location", "")
                    code = self._extract_code_from_url(location2)
                    if code:
                        logger.info(f"  获取到 authorization code: {code[:20]}...")
                        return code

        # 如果上面的流程没有拿到 code，尝试从响应体提取
        code = self._extract_code_from_url(resp.text)
        if code:
            return code

        raise AuthFlowError(f"Step 8 失败: 无法获取 authorization code (HTTP {resp.status_code})")

    def _extract_code_from_url(self, url_or_text: str) -> Optional[str]:
        """从 URL 或文本中提取 OAuth authorization code。"""
        # 从 URL 查询参数提取
        match = re.search(r'[?&]code=([a-zA-Z0-9._-]+)', url_or_text)
        if match:
            return match.group(1)
        return None

    # ── Step 9: Code 换 Token ───────────────────────────────

    def _exchange_code_for_tokens(self, auth_code: str) -> dict:
        """
        POST https://auth0.openai.com/oauth/token

        用 authorization code + code_verifier 换取 access_token 和 refresh_token。
        """
        logger.info("Step 9: 用 authorization code 换取 token...")

        data = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": auth_code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": self.code_verifier,
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": CHATGPT_BASE,
            "Referer": CHATGPT_BASE,
        }

        resp = self.client.post(
            AUTH0_OAUTH_TOKEN_URL,
            data=data,
            headers=headers,
        )

        if resp.status_code != 200:
            error_detail = resp.text[:500]
            raise AuthFlowError(
                f"Token 交换失败 (HTTP {resp.status_code}): {error_detail}"
            )

        try:
            tokens = resp.json()
        except Exception:
            raise AuthFlowError(f"Token 响应解析失败: {resp.text[:500]}")

        # 验证必要字段
        if "access_token" not in tokens:
            raise AuthFlowError(f"Token 响应缺少 access_token: {list(tokens.keys())}")

        logger.info(f"  access_token 长度: {len(tokens.get('access_token', ''))}")
        logger.info(f"  refresh_token: {'有' if tokens.get('refresh_token') else '无'}")
        logger.info(f"  expires_in: {tokens.get('expires_in', 'N/A')}s")

        return tokens

    # ── 辅助方法 ─────────────────────────────────────────────

    def _inject_pkce(self, url: str) -> str:
        """向 Auth0 authorize URL 注入 PKCE 参数。"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # 替换或添加 PKCE 参数
        params["code_challenge"] = [self.code_challenge]
        params["code_challenge_method"] = ["S256"]

        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def _handle_auth0_response(self, resp: Response, step_name: str) -> tuple[str, bool]:
        """
        处理 Auth0 表单提交的响应。

        Auth0 可能返回：
        - 302 重定向（成功或下一步）
        - 200 HTML 页面（错误或需要额外操作）

        Returns:
            (new_state, needs_mfa)
        """
        # 处理重定向
        if resp.status_code in (302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            logger.debug(f"  {step_name} 重定向 → {location[:100]}")

            # 检测 MFA
            if "mfa-email-challenge" in location:
                new_state = self._extract_state_from_url(location)
                if new_state:
                    logger.info("  需要邮箱验证码 (MFA)")
                    return new_state, True
                raise AuthFlowError(f"{step_name}: 检测到 MFA 但无法提取 state")

            # 检测成功或下一步
            new_state = self._extract_state_from_url(location)
            if new_state:
                return new_state, False

            # 如果重定向到 authorize/resume，提取 state
            if "authorize/resume" in location:
                return location, False

            raise AuthFlowError(
                f"{step_name}: 意外的重定向 ({location[:200]})"
            )

        # 处理 HTML 响应（可能包含错误或下一步表单）
        if resp.status_code == 200:
            html = resp.text

            # 检查是否有错误消息
            error_match = re.search(
                r'(?:error|wrong|invalid|incorrect|not\s+found|doesn\'t\s+exist)[^<]*',
                html, re.IGNORECASE
            )
            if error_match:
                # 尝试提取更具体的错误
                detail_match = re.search(
                    r'<p[^>]*class="[^"]*error[^"]*"[^>]*>([^<]+)</p>',
                    html, re.IGNORECASE
                )
                if detail_match:
                    raise AuthFlowError(f"{step_name}: {detail_match.group(1).strip()}")
                raise AuthFlowError(f"{step_name}: 登录被拒绝（密码错误或账号问题）")

            # 可能是需要额外确认的页面（MFA 选择页等）
            if "mfa" in html.lower() or "verify" in html.lower():
                new_state = self._extract_transaction_state(html)
                if new_state:
                    return new_state, True

            # 可能是 Auth0 返回的下一步表单页面（非重定向模式）
            # 尝试从表单 action 中提取 state
            new_state = self._extract_transaction_state(html)
            if new_state:
                logger.debug(f"  {step_name}: 从 HTML 表单提取到 state")
                # 检测是否需要 MFA
                needs_mfa = bool(
                    re.search(r'mfa|challenge|verify|code', html, re.IGNORECASE)
                )
                return new_state, needs_mfa

            raise AuthFlowError(
                f"{step_name}: 收到 HTML 页面但无法解析下一步 "
                f"(HTTP {resp.status_code}, 页面长度 {len(html)})"
            )

        # 其他状态码
        if resp.status_code == 429:
            raise AuthFlowError(f"{step_name}: 触发频率限制 (HTTP 429)")

        raise AuthFlowError(
            f"{step_name}: 意外的 HTTP 状态码 {resp.status_code}"
        )

    def _extract_state_from_url(self, url: str) -> Optional[str]:
        """从 URL 中提取 state 参数。"""
        match = re.search(r'[?&]state=([a-zA-Z0-9_-]+)', url)
        if match:
            return match.group(1)
        return None
