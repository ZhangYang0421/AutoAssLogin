"""
模块1: 完整 AAS 注册
登录 → 启用 AAS → 注册 Passkey → 持久化凭据和恢复密钥。

用法:
  python aas_enroll.py --account 1.txt --index N
  python aas_enroll.py --account 1.txt --index N --visible
"""
import sys
import time
import re
import json
from pathlib import Path

# 允许直接运行
sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import (
    load_account, parse_mailbox_params, generate_uid,
    create_browser_context, extract_session_token, save_session_token,
    setup_webauthn, add_virtual_authenticator,
    save_passkey_credential, load_passkey_credentials,
    save_recovery_keys, EmailPoller,
    fill_input, click_button, wait_for_continue_enabled,
    create_cli_parser, screenshot,
)

from playwright.sync_api import sync_playwright


def enroll_aas(account, proxy, headless=True, debug=False):
    """完整 AAS 注册流程，返回 session dict 或 None"""
    email = account["email"]
    password = account.get("password", "")
    mailbox_url = account.get("mailbox_url", "")
    uid = generate_uid(email)

    if not mailbox_url:
        print("[FAIL] 账号缺少 mailbox_url 字段")
        return None

    mail = parse_mailbox_params(mailbox_url)
    proxies = {"http": proxy, "https": proxy}
    poller = EmailPoller(
        {"base": mail["base"], "api_key": mail["api_key"],
         "pt": mail["pt"], "email": email},
        proxies=proxies,
    )

    print(f"\n{'='*60}")
    print(f"AAS 注册: {email}")
    print(f"{'='*60}")

    session = None
    keys = []

    with sync_playwright() as pw:
        ctx, page = create_browser_context(pw, uid, proxy=proxy, headless=headless)
        cdp = setup_webauthn(page)

        # ================================================================
        # Step 1: 登录（邮箱 + OTP / 密码）
        # ================================================================
        print("\n--- Step 1: 登录 ---")
        page.goto("https://chatgpt.com/auth/login",
                  wait_until="domcontentloaded", timeout=60000)
        time.sleep(3)

        # 1a: 填邮箱
        fill_input(page, ['input[name="email"]'], email)
        print(f"  已填邮箱: {email}")
        time.sleep(0.5)
        click_button(page, ['button[type="submit"]', 'button:has-text("继续")'])
        time.sleep(5)

        print(f"  提交邮箱后 URL: {page.url[:120]}")
        screenshot(page, uid, "s1_email", debug)

        # 1b: 密码页（如果有）
        body = page.evaluate("() => document.body.innerText")
        if "password" in page.url.lower() or "密码" in body:
            print("  → 密码页")
            if password:
                fill_input(page,
                           ['input[name="password"]', 'input[type="password"]'],
                           password)
                time.sleep(0.5)
                click_button(page,
                             ['button[type="submit"]', 'button:has-text("继续")'])
                time.sleep(8)
                print(f"  提交密码后 URL: {page.url[:120]}")
            else:
                print("  [WARN] 账号缺少 password，尝试跳过密码页...")
                click_button(page, ['button:has-text("一次性验证码")'], timeout=5000)
                time.sleep(5)

        # 1c: 邮箱验证（登录阶段）
        body = page.evaluate("() => document.body.innerText")
        cur_url = page.url

        # 处理内联表单中的 OTP 按钮
        if "一次性验证码" in body:
            print("  → 点击 OTP 按钮")
            click_button(page,
                         ['button._inlinePasswordlessLogin_19q13_6',
                          'button:has-text("一次性验证码")'],
                         timeout=5000)
            time.sleep(5)
            body = page.evaluate("() => document.body.innerText")
            cur_url = page.url
            print(f"  OTP 后页面: {body[:100]}")

        # 等待跳转到验证页
        if "email-verification" not in cur_url and "code" not in body.lower():
            print("  等待跳转到验证页...")
            click_button(page, ['button:has-text("继续")'], timeout=2000)
            time.sleep(3)
            body = page.evaluate("() => document.body.innerText")
            cur_url = page.url

        if "email-verification" in cur_url or "验证码" in body or "check your inbox" in body.lower():
            print("  → 邮箱验证")
            # 简单轮询获取验证码（登录阶段，不严格要求基线对比）
            time.sleep(5)
            code = None
            for i in range(30):
                c, _ = poller.get_latest()
                if c and len(str(c)) >= 4:
                    code = c
                    print(f"  验证码: {code}")
                    break
                time.sleep(5)

            if code:
                fill_input(page, ['input[name="code"]'], code)
                time.sleep(0.5)
                click_button(page,
                             ['button[type="submit"]', 'button:has-text("继续")'])
                # 等待登录完成
                try:
                    page.wait_for_url("https://chatgpt.com/*", timeout=30000)
                    for _ in range(15):
                        time.sleep(2)
                        if "/auth/" not in page.url:
                            break
                except Exception:
                    pass
                print(f"  登录后 URL: {page.url[:120]}")
            else:
                print("[FAIL] 登录阶段未收到验证码")
                ctx.close()
                return None

        # ================================================================
        # 检查是否已有 AAS
        # ================================================================
        if "passkey" in page.url:
            print("\n[WARN] 该账号已启用 AAS（重定向到 passkey 登录）")
            print("  请使用 login_passkey.py 登录")
            print("  或使用 login_password.py 然后手动管理 AAS")
            ctx.close()
            return None

        # ================================================================
        # Step 2: 触发 AAS
        # ================================================================
        print("\n--- Step 2: 触发 AAS ---")
        page.goto("https://chatgpt.com/advanced-account-security", timeout=30000)
        time.sleep(4)
        screenshot(page, uid, "s2_aas_page", debug)

        body = page.evaluate("() => document.body.innerText")
        if "已启用" in body and "加入" not in body:
            print("[INFO] AAS 已启用，无需重复注册")
            ctx.close()
            return None

        # 获取邮箱基线（后续 AAS 验证需要对比）
        baseline_code, baseline_time = poller.get_latest()
        print(f"  邮箱基线: code={baseline_code}, time={baseline_time}")

        # 点击"加入"
        clicked = click_button(page, [
            'button:has-text("加入高级账户安全")',
            'button:has-text("加入")',
        ])
        if clicked:
            print("  已点击加入")
            # 等待跳转到 auth.openai.com
            try:
                page.wait_for_url("**/auth.openai.com/**", timeout=30000)
            except Exception:
                print("  等待跳转超时")
            time.sleep(3)
            print(f"  跳转到: {page.url[:150]}")
        screenshot(page, uid, "s2_after_join", debug)

        # ================================================================
        # Step 3: AAS 重新认证 + 邮箱验证
        # ================================================================
        cur_url = page.url
        body = page.evaluate("() => document.body.innerText")

        if "auth.openai.com" in cur_url or "email-verification" in cur_url:
            print("\n--- Step 3: AAS 重新认证 ---")

            # 3a: 处理内联表单中的 OTP 按钮（如果有）
            if "一次性验证码" in body:
                print("  → 点击 OTP 按钮")
                click_button(page,
                             ['button._inlinePasswordlessLogin_19q13_6',
                              'button:has-text("一次性验证码")'],
                             timeout=5000)
                time.sleep(5)
                body = page.evaluate("() => document.body.innerText")
                print(f"  OTP 后页面: {body[:150]}")

            # 3b: 密码重认证（如果需要）
            if "password" in page.url.lower() or "密码" in body:
                print("  → 密码重认证")
                if password:
                    fill_input(page,
                               ['input[name="password"]', 'input[type="password"]'],
                               password)
                    time.sleep(0.5)
                    click_button(page,
                                 ['button[type="submit"]', 'button:has-text("继续")'])
                    time.sleep(5)
                else:
                    print("  [WARN] 缺少密码")

            # 3c: 邮箱验证（AAS 阶段，需要基线对比）
            body = page.evaluate("() => document.body.innerText")
            if "检查你的收件箱" in body or "输入我们刚刚向" in body or "email-verification" in page.url:
                print("\n  → AAS 邮箱验证（等待新邮件）...")
                screenshot(page, uid, "s3_vfy", debug)

                def resend():
                    print("    点击重新发送...")
                    click_button(page, [
                        'button:has-text("重新发送")',
                        'a:has-text("重新发送")',
                    ], timeout=2000)

                aas_code = poller.wait_for_code(
                    timeout=900,  # 15 分钟
                    interval=5,
                    baseline_code=baseline_code,
                    baseline_time=baseline_time,
                    resend_callback=resend,
                )

                if aas_code:
                    fill_input(page, ['input[name="code"]'], aas_code)
                    time.sleep(0.5)
                    click_button(page,
                                 ['button[type="submit"]', 'button:has-text("继续")'])
                    time.sleep(8)
                    screenshot(page, uid, "s3_post_code", debug)
                else:
                    print("[FAIL] AAS 验证码超时")
                    ctx.close()
                    return None

        # ================================================================
        # Step 4: 注册 Passkey（CDP 捕获凭据）
        # ================================================================
        print("\n--- Step 4: 注册 Passkey (捕获凭据) ---")

        # 创建 2 个虚拟认证器用于捕获
        for transport in ["internal", "usb"]:
            add_virtual_authenticator(cdp, transport=transport)

        captured_creds = []

        def on_credential_added(params):
            captured_creds.append(params)
            cred = params.get("credential", {})
            idx = len(captured_creds)
            print(f"\n  *** 捕获 Passkey #{idx} ***")
            print(f"  credentialId: {cred.get('credentialId', '?')[:60]}")
            print(f"  rpId: {cred.get('rpId', '?')}")
            save_passkey_credential(uid, params, idx)

        cdp.on("WebAuthn.credentialAdded", on_credential_added)

        time.sleep(3)
        screenshot(page, uid, "s4_methods", debug)

        # 确保在 secure-methods 页面
        if "/secure-methods" not in page.url:
            click_button(page, ['button:has-text("继续")', 'a:has-text("继续")'])
            time.sleep(5)

        # 添加 2 个 passkeys
        for key_num in [1, 2]:
            print(f"\n  添加 Passkey #{key_num}...")
            time.sleep(2)

            # 关闭可能的弹窗
            try:
                page.keyboard.press("Escape")
                time.sleep(0.5)
            except Exception:
                pass

            # 点击"添加"按钮
            add_btns = [b for b in page.query_selector_all('button:has-text("添加")')
                       if b.is_visible() and b.is_enabled()]
            if not add_btns:
                print("  没有更多添加按钮")
                break

            add_btns[0].click()
            print("  已点击添加")
            time.sleep(2)

            # 选择"通行密钥"选项
            click_button(page, [
                'button._addMethodMenuItem_1kkaj_300:has-text("通行密钥")',
                '[data-dd-action-name*="Passkey"]',
            ], timeout=5000)
            time.sleep(5)

            print(f"  Passkey #{key_num} 完成")

            # 处理"知道了"弹窗（重复 passkey 提示）
            try:
                dup = page.wait_for_selector('button:has-text("知道了")', timeout=3000)
                if dup and dup.is_visible():
                    dup.click()
                    time.sleep(2)
                    print("  点击了'知道了'")
            except Exception:
                pass

        print(f"\n  共捕获 {len(captured_creds)} 个凭据")
        screenshot(page, uid, "s4_keys", debug)

        # 等待"继续"按钮启用并点击
        wait_for_continue_enabled(page, label="继续", max_wait=15)

        # ================================================================
        # Step 5: 恢复密钥
        # ================================================================
        print("\n--- Step 5: 恢复密钥 ---")
        time.sleep(3)

        body = page.evaluate("() => document.body.innerText")

        # 如果还在"保存恢复密钥"介绍页，先点继续到生成页
        if "保存恢复密钥" in body and "/generate" not in page.url:
            print("  在恢复密钥介绍页，点继续...")
            click_button(page, ['button:has-text("继续")', 'a:has-text("继续")'])
            time.sleep(3)

        body = page.evaluate("() => document.body.innerText")

        # 提取恢复密钥（格式: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX...）
        keys = re.findall(
            r'([A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9])',
            body,
        )
        if keys:
            recovery_keys = list(dict.fromkeys(keys))  # 去重保序
            print(f"  *** 恢复密钥 ({len(recovery_keys)} 个) ***")
            for i, k in enumerate(recovery_keys, 1):
                print(f"  {i}. {k}")
            save_recovery_keys(uid, email, recovery_keys)

            # 勾选"我已保存"复选框
            try:
                label = page.wait_for_selector(
                    "._savedCheckboxLabel_1tz9e_175", timeout=5000)
                if label:
                    label.click()
                    time.sleep(1)
                    print("  已勾选确认复选框")
            except Exception:
                # 尝试其他复选框选择器
                try:
                    cb = page.wait_for_selector(
                        'input[type="checkbox"]', timeout=3000)
                    if cb:
                        cb.click()
                        time.sleep(1)
                        print("  已勾选复选框")
                except Exception:
                    pass

            # 等待"继续"按钮启用
            wait_for_continue_enabled(page, label="继续", max_wait=10)
        else:
            print("  [WARN] 未检测到恢复密钥")
            screenshot(page, uid, "s5_no_keys", debug=True)

        # ================================================================
        # Step 6: 最终确认
        # ================================================================
        print("\n--- Step 6: 最终确认 ---")
        time.sleep(3)

        body = page.evaluate("() => document.body.innerText")
        print(f"  最终页面: {body[:200]}")

        click_button(page, [
            'button:has-text("注册")',
            'button:has-text("Enroll")',
            'button:has-text("完成")',
        ])
        time.sleep(8)

        screenshot(page, uid, "s6_final", debug)
        print(f"  最终 URL: {page.url[:200]}")

        # ================================================================
        # 提取 session token
        # ================================================================
        print("\n--- 提取 session token ---")
        if "chatgpt.com" in page.url and "/auth/" not in page.url:
            session = extract_session_token(page)
            if session:
                print(f"  User: {session.get('user', {}).get('email', '?')}")
                print(f"  Token: {session.get('accessToken', '')[:40]}...")
                save_session_token(email, session)
            else:
                print("  未能提取 token")
        else:
            print(f"  不在 chatgpt 首页: {page.url[:100]}")

        # ================================================================
        # 汇总
        # ================================================================
        print(f"\n{'='*60}")
        print(f"AAS 注册完成！")
        print(f"  Passkey 凭据: {len(captured_creds)} 个 (已持久化)")
        print(f"  恢复密钥: {len(keys) if keys else 0} 个")
        print(f"  下次登录: python login_passkey.py --account {sys.argv[1] if len(sys.argv) > 1 else '1.txt'} --index 0")
        print(f"{'='*60}")

        ctx.close()
        return session


def main():
    parser = create_cli_parser(description="完整 AAS 注册 — 登录 + 启用 AAS + 注册 Passkey + 持久化凭据")
    args = parser.parse_args()

    account = load_account(args.account, args.index)
    if not account:
        print(f"[FAIL] 未找到账号 index={args.index} 在 {args.account}")
        return

    # 检查是否已有 passkey 凭据
    email = account["email"]
    uid = generate_uid(email)
    existing = load_passkey_credentials(uid)
    if existing:
        print(f"[INFO] 已存在 {len(existing)} 个 passkey 凭据")
        print(f"  如需登录请使用: python login_passkey.py --account {args.account} --index {args.index}")
        cont = input("  是否重新注册？(y/N): ").strip().lower()
        if cont not in ("y", "yes"):
            print("已取消")
            return

    result = enroll_aas(
        account, args.proxy,
        headless=not args.visible,
        debug=args.debug,
    )

    if result:
        print("\nAAS 注册并登录成功！")
    else:
        print("\nAAS 注册完成（请检查以上输出确认状态）")


if __name__ == "__main__":
    main()
