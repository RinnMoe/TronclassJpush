"""Composition root for the JPush monitoring MVP."""

from __future__ import annotations

import argparse
from collections.abc import Iterable
from typing import Any

from auth_adapter import Authenticator, build_chu_authenticator
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
        "--sdk-path",
        help="CHUAuthSDK 本地目录；未提供时使用 CHUAUTHSDK_PATH 或演示路径。",
    )
    parser.add_argument(
        "--alias",
        help="登录后要绑定的 JPush alias；不传则只完成设备注册。",
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


def run(authenticator: Authenticator, source: Iterable[Any]) -> None:
    """Run the monitor with injected authentication and push transport."""

    print("通过外部认证 SDK 获取身份；主程序不读取账号、密码或业务地址。")
    context = authenticator.authenticate()
    display_name = (
        context.user_info.get("cn")
        or context.user_info.get("name")
        or "unknown"
    )
    print(f"统一身份认证完成：{display_name}")

    JPushMonitor(
        config=JPushConfig.changke_demo(),
        source=source,
        handler=handle_push_event,
    ).run()


def main(argv: list[str] | None = None) -> None:
    args = build_argument_parser().parse_args(argv)
    config = JPushConfig.changke_demo()
    if args.stdin:
        source = JsonLineJPushSource()
    else:
        source = PythonJPushSource(
            config=config,
            store_path=args.store,
            alias=args.alias,
            servers=args.server,
        )
    run(build_chu_authenticator(args.sdk_path), source)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("用户中断，程序退出。")
    except Exception as exc:  # noqa: BLE001 - keep the CLI failure concise
        print(f"程序退出：{exc}")
