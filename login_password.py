"""
模块2: 密码 + OTP 登录
传统邮箱 + 密码 + 验证码登录，直接获取 session token（不使用 WebAuthn）。

用法:
  python login_password.py --account 3.txt --index 0
  python login_password.py --account 3.txt --index 0 --visible
"""
import sys
import time
from pathlib import Path

# 允许直接运行
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (
    load_account, parse_mailbox_params, generate_uid,
    create_browser_context, extract_session_token, save_session_token,
    EmailPoller, fill_input, click_button, create_cli_parser, screenshot,
)

from playwright.sync_api import sync_playwright


def login_via_password(account, proxy, headless=True, debug=False):
    """密码 + OTP 登录流程，返回 session dict 或 None"""
    email = account["email"]
    password = account.get("password", "")
    mailbox_url = account.get("mailbox_url", "")

    if not password:
        print("[FAIL] 账号缺少 password 字段")
        return None
    if not mailbox_url:
        print("[FAIL] 账号缺少 mailbox_url 字段")
        return None

    uid = generate_uid(email)
    mail = parse_mailbox_params(mailbox_url)
    proxies = {"http": proxy, "https": proxy}
    poller = EmailPoller(
        {"base": mail["base"], "api_key": mail["api_key"],
         "pt": mail["pt"], "email": email},
        proxies=proxies,
    )

    print(f"\n{'='*60}")
    print(f"密码登录: {email}")
    print(f"{'='*60}")

    with sync_playwright() as pw:
        ctx, page = create_browser_context(pw, uid, proxy=proxy, headless=headless)

        # --- Step 1: 打开登录页，填邮箱 ---
        print("\n[1] 填写邮箱...")
        page.goto("https://chatgpt.com/auth/login",
                  wait_until="domcontentloaded", timeout=60000)
        time.sleep(3)

        fill_input(page, ['input[name="email"]'], email)
        time.sleep(0.5)
        click_button(page, ['button[type="submit"]', 'button:has-text("继续")'])
        time.sleep(5)

        print(f"  提交邮箱后 URL: {page.url[:120]}")
        screenshot(page, uid, "step1_email", debug)

        # --- Step 2: 密码页 ---
        body = page.evaluate("() => document.body.innerText")

        # 检查是否遇到 passkey 挑战
        if "passkey" in page.url or "通行密钥" in body or "使用密钥" in body:
            print("\n[WARN] 检测到 passkey 登录流程，请使用 login_passkey.py")
            ctx.close()
            return None

        if "password" in page.url.lower() or "密码" in body:
            print("\n[2] 填写密码...")
            fill_input(page,
                       ['input[name="password"]', 'input[type="password"]'],
                       password)
            time.sleep(0.5)
            click_button(page,
                         ['button[type="submit"]', 'button:has-text("继续")'])
            time.sleep(8)
            print(f"  提交密码后 URL: {page.url[:120]}")
            screenshot(page, uid, "step2_password", debug)

        # --- Step 3: 邮箱验证页 ---
        body = page.evaluate("() => document.body.innerText")
        cur_url = page.url

        if "email-verification" not in cur_url and "code" not in body.lower():
            # 尝试点击继续按钮（可能还在过渡页面）
            print("  等待跳转到验证页...")
            click_button(page, ['button:has-text("继续")'], timeout=2000)
            time.sleep(5)
            body = page.evaluate("() => document.body.innerText")
            cur_url = page.url

        if "email-verification" in cur_url or "验证码" in body or "check your inbox" in body.lower():
            print("\n[3] 邮箱验证...")

            # 获取基线
            baseline_code, baseline_time = poller.get_latest()
            print(f"  基线: code={baseline_code}, time={baseline_time}")

            def resend():
                print("  点击重新发送...")
                click_button(page, [
                    'button:has-text("重新发送")',
                    'a:has-text("重新发送")',
                ], timeout=2000)

            # 先等待一小段时间看是否自动收到
            code = None
            for i in range(12):
                time.sleep(5)
                c, recv = poller.get_latest()
                if c and recv and (recv != baseline_time or c != baseline_code):
                    if c and len(str(c)) >= 4:
                        code = c
                        print(f"  *** 自动收到验证码: {code} ***")
                        break

            # 没自动收到则主动重新发送并等待
            if not code:
                resend()
                time.sleep(3)
                code = poller.wait_for_code(
                    timeout=300, interval=5,
                    baseline_code=baseline_code,
                    baseline_time=baseline_time,
                    resend_callback=resend,
                )

            if code:
                fill_input(page, ['input[name="code"]'], code)
                time.sleep(0.5)
                click_button(page,
                             ['button[type="submit"]', 'button:has-text("继续")'])
                time.sleep(10)

                # 等待登录完成
                try:
                    page.wait_for_url("https://chatgpt.com/*", timeout=30000)
                    for _ in range(15):
                        time.sleep(2)
                        if "/auth/" not in page.url:
                            break
                except Exception:
                    pass
                print(f"  提交验证码后 URL: {page.url[:120]}")
            else:
                print("[FAIL] 未收到验证码，超时")
                ctx.close()
                return None
        else:
            # 可能没有验证步骤，直接登录了
            print(f"  当前页面: {cur_url[:120]}")
            if "chatgpt.com" in cur_url and "/auth/" not in cur_url:
                print("  无需验证，已登录")

        # --- Step 4: 提取 session token ---
        print("\n[4] 提取 session token...")
        if "chatgpt.com" in page.url and "/auth/" not in page.url:
            session = extract_session_token(page)
            if session:
                print(f"  *** 登录成功！***")
                print(f"  User: {session.get('user', {}).get('email', '?')}")
                print(f"  Token: {session.get('accessToken', '')[:40]}...")
                save_session_token(email, session)
                ctx.close()
                return session
            else:
                print(f"  未能提取 session token，可能未登录")
        else:
            print(f"  登录未完成，当前 URL: {page.url[:120]}")

        screenshot(page, uid, "final", debug)
        ctx.close()

    return None


def main():
    parser = create_cli_parser(description="密码 + OTP 登录 — 直接获取 session token")
    args = parser.parse_args()

    account = load_account(args.account, args.index)
    if not account:
        print(f"[FAIL] 未找到账号 index={args.index} 在 {args.account}")
        return

    result = login_via_password(
        account, args.proxy,
        headless=not args.visible,
        debug=args.debug,
    )

    if result:
        print(f"\n{'='*60}")
        print("登录成功！")
        print(f"  Token 已保存到 tokens/token/")
        print(f"{'='*60}")
    else:
        print(f"\n{'='*60}")
        print("登录失败！")
        print(f"  如果遇到 passkey 挑战，请使用 login_passkey.py")
        print(f"{'='*60}")


if __name__ == "__main__":
    main()
