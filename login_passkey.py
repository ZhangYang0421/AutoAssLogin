"""
模块3: Passkey 凭据登录
加载已保存的 passkey 凭据 → 导入虚拟认证器 → 登录 → 获取 session token。

用法:
  python login_passkey.py --account 1.txt --index 0
  python login_passkey.py --account 1.txt --index 0 --visible
"""
import sys
import time
import json
from pathlib import Path

# 允许直接运行
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (
    load_account, parse_mailbox_params, generate_uid,
    create_browser_context, extract_session_token, save_session_token,
    setup_webauthn, add_virtual_authenticator, import_credential,
    load_passkey_credentials, fill_input, click_button,
    create_cli_parser, screenshot,
)

from playwright.sync_api import sync_playwright


def login_via_passkey(account, proxy, headless=True, debug=False):
    """Passkey 凭据登录流程，返回 session dict 或 None"""
    email = account["email"]
    uid = generate_uid(email)

    print(f"\n{'='*60}")
    print(f"Passkey 登录: {email}")
    print(f"{'='*60}")

    # 加载已保存的 passkey 凭据
    saved_creds = load_passkey_credentials(uid)
    if not saved_creds:
        print("[FAIL] 没有已保存的 passkey 凭据")
        print(f"  请先运行 aas_enroll.py 注册 passkey")
        print(f"  或使用 login_password.py 进行密码登录")
        return None

    print(f"[凭据] 加载了 {len(saved_creds)} 个 passkey 凭据")

    with sync_playwright() as pw:
        ctx, page = create_browser_context(pw, uid, proxy=proxy, headless=headless)
        cdp = setup_webauthn(page)

        # --- 导入凭据 ---
        # 每个凭据需要独立的虚拟认证器（Chrome 限制：每种 transport 只能一个）
        transports = ["internal", "usb", "nfc", "ble"]
        print(f"\n[导入] {len(saved_creds)} 个凭据...")
        for i, cred_data in enumerate(saved_creds):
            transport_key = transports[i % len(transports)]
            auth_id = add_virtual_authenticator(cdp, transport=transport_key)
            import_credential(cdp, auth_id, cred_data["credential"])
            cred_id = cred_data["credential"].get("credentialId", "?")[:40]
            print(f"  + {cred_id}... [{transport_key}]")

        # --- 导航登录 ---
        print("\n[1] 登录...")
        page.goto("https://chatgpt.com/auth/login",
                  wait_until="domcontentloaded", timeout=60000)
        time.sleep(3)

        fill_input(page, ['input[name="email"]'], email)
        time.sleep(0.5)
        click_button(page, ['button[type="submit"]', 'button:has-text("继续")'])
        time.sleep(5)

        print(f"  提交邮箱后 URL: {page.url[:150]}")
        screenshot(page, uid, "step1_email", debug)

        # --- 处理 passkey 挑战 ---
        body = page.evaluate("() => document.body.innerText")

        if "passkey" in page.url or "通行密钥" in body or "使用密钥" in body:
            print("\n[2] 处理 passkey 挑战...")
            click_button(page, [
                'button:has-text("使用密钥继续")',
                'button:has-text("继续")',
            ])
            time.sleep(8)

            print(f"  认证后 URL: {page.url[:200]}")
            screenshot(page, uid, "after_passkey", debug)

            # 检查是否认证失败
            if "challenge" in page.url or "passkey" in page.url:
                print("[WARN] 凭据认证失败，可能需要重新注册")
                print("  请运行: python aas_enroll.py --account ... --index ...")
                ctx.close()
                return None

        # --- 提取 session token ---
        print("\n[3] 提取 session token...")
        if "chatgpt.com" in page.url and "/auth/" not in page.url:
            session = extract_session_token(page)
            if session:
                at = session.get("accessToken", "")
                if at:
                    print(f"\n  *** 登录成功！***")
                    print(f"  User: {session.get('user', {}).get('email', '?')}")
                    print(f"  Token: {at[:40]}...")
                    save_session_token(email, session)
                    ctx.close()
                    return session
                else:
                    print(f"  未登录: session 中无 accessToken")
            else:
                # 尝试从 URL 判断
                print(f"  未能提取 session token")
        else:
            print(f"  登录未完成，当前 URL: {page.url[:120]}")

        screenshot(page, uid, "final", debug)
        ctx.close()

    return None


def main():
    parser = create_cli_parser(description="Passkey 凭据登录 — 使用已保存的 WebAuthn 凭据")
    args = parser.parse_args()

    account = load_account(args.account, args.index)
    if not account:
        print(f"[FAIL] 未找到账号 index={args.index} 在 {args.account}")
        return

    result = login_via_passkey(
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
        print(f"  未保存过 passkey 凭据请先运行 aas_enroll.py")
        print(f"  密码登录请使用 login_password.py")
        print(f"{'='*60}")


if __name__ == "__main__":
    main()
