"""Composition root for the JPush monitoring MVP."""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterable
from typing import Any

from account_binding import AccountBindingConfig, fetch_jpush_binding
from auth_adapter import AuthContext, Authenticator, build_external_authenticator
from event_handler import handle_push_event
from jpush_monitor import (
    JPushConfig,
    JPushMonitor,
    JsonLineJPushSource,
    PythonJPushSource,
)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="JPush 签到事件监测 MVP")
    parser.add_argument(
        "--alias",
        help="调试覆盖自动获取的 JPush alias；默认从登录账号自动获取。",
    )
    parser.add_argument(
        "--tag",
        dest="tags",
        action="append",
        default=[],
        help="调试覆盖自动获取的 JPush tag；可重复传入，默认从登录账号自动获取。",
    )
    parser.add_argument(
        "--store",
        default="data/jpush/credentials.json",
        help="JPush 设备凭证持久化路径。",
    )
    parser.add_argument(
        "--server",
        action="append",
        default=[],
        metavar="HOST:PORT",
        help="可选的 JPush 长连接地址；可重复传入，默认使用 SIS 服务发现。",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="从 stdin 读取 JSON Lines，仅用于本地回归测试。",
    )
    return parser


def run(
    authenticator: Authenticator,
    source: Iterable[Any] | Callable[[AuthContext], Iterable[Any]],
) -> None:
    """Authenticate first, then create the account-aware push source."""

    print("通过外部认证 SDK 获取身份；主程序不读取账号、密码或业务地址。")
    context = authenticator.authenticate()
    display_name = (
        context.user_info.get("cn")
        or context.user_info.get("name")
        or "unknown"
    )
    print(f"统一身份认证完成：{display_name}")

    resolved_source = source(context) if callable(source) else source

    JPushMonitor(
        config=JPushConfig.tronclass_demo(),
        source=resolved_source,
        handler=handle_push_event,
    ).run()


def main(argv: list[str] | None = None) -> None:
    args = build_argument_parser().parse_args(argv)
    config = JPushConfig.tronclass_demo()
    authenticator = build_external_authenticator()

    def build_source(context: AuthContext) -> Iterable[Any]:
        if args.stdin:
            return JsonLineJPushSource()

        if args.alias is not None or args.tags:
            alias = args.alias or ""
            tags = tuple(args.tags)
            print(
                "使用命令行 JPush 绑定覆盖："
                f"tags={len(tags)}，alias={'yes' if alias else 'no'}"
            )
        else:
            binding = fetch_jpush_binding(
                context.session,
                AccountBindingConfig.tronclass_demo(),
            )
            alias = binding.alias
            tags = binding.tags
            print(
                "已从登录账号获取 JPush 绑定："
                f"tags={len(tags)}，alias=yes"
            )

        return PythonJPushSource(
            config=config,
            store_path=args.store,
            alias=alias or None,
            tags=tags,
            servers=args.server,
        )

    run(authenticator, build_source)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("用户中断，程序退出。")
    except Exception as exc:  # noqa: BLE001 - keep the CLI failure concise
        print(f"程序退出：{exc}")
