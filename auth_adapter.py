"""Generic authentication boundary for the JPush MVP.

The monitor only needs an authenticated context. The concrete SDK module,
factory and method names are supplied at runtime, so this repository does not
contain campus-specific authentication details.
"""

from __future__ import annotations

import importlib
import json
import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class AuthContext:
    """Result supplied by an external authentication SDK."""

    session: Any
    user_info: Mapping[str, Any]


class Authenticator(Protocol):
    """Minimal contract required by the application composition root."""

    def authenticate(self) -> AuthContext:
        ...


class CallableAuthenticator:
    """Adapt any authentication callable to ``Authenticator``."""

    def __init__(self, authenticate: Callable[[], AuthContext]):
        self._authenticate = authenticate

    def authenticate(self) -> AuthContext:
        return self._authenticate()


class ExternalSdkAuthenticator:
    """Adapt an externally supplied SDK object to ``Authenticator``."""

    def __init__(
        self,
        auth_factory: Callable[[], Any],
        login_method: str,
        user_info_method: str,
    ):
        self._auth_factory = auth_factory
        self._login_method = login_method
        self._user_info_method = user_info_method

    def authenticate(self) -> AuthContext:
        auth = self._auth_factory()
        login = _require_callable(auth, self._login_method)
        user_info_loader = _require_callable(auth, self._user_info_method)
        session = login()
        user_info = user_info_loader()
        if not isinstance(user_info, Mapping):
            raise TypeError("外部认证 SDK 的用户信息必须是映射对象。")
        return AuthContext(session=session, user_info=dict(user_info))


def _require_callable(target: Any, name: str) -> Callable[[], Any]:
    value = getattr(target, name, None)
    if not callable(value):
        raise TypeError(f"外部认证对象缺少可调用方法：{name}")
    return value


def _load_external_module(
    module_name: str,
    sdk_path: str | os.PathLike[str] | None = None,
) -> Any:
    if sdk_path:
        path = Path(sdk_path)
        if not path.is_dir():
            raise RuntimeError(f"外部认证 SDK 路径不存在：{path}")
        path_text = str(path)
        if path_text not in sys.path:
            sys.path.insert(0, path_text)

    try:
        return importlib.import_module(module_name)
    except ImportError as exc:
        raise RuntimeError(
            f"无法加载外部认证 SDK 模块：{module_name}；"
            "请检查 SDK 路径和运行时依赖。"
        ) from exc


def _parse_constructor_kwargs(
    value: str | Mapping[str, Any] | None,
) -> dict[str, Any]:
    if value is None:
        value = os.environ.get("AUTH_SDK_CONSTRUCTOR_KWARGS", "{}")
    if isinstance(value, Mapping):
        return dict(value)
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "AUTH_SDK_CONSTRUCTOR_KWARGS 必须是 JSON 对象。"
        ) from exc
    if not isinstance(parsed, dict):
        raise TypeError("AUTH_SDK_CONSTRUCTOR_KWARGS 必须是 JSON 对象。")
    return parsed


def build_external_authenticator(
    *,
    module_name: str | None = None,
    factory_name: str | None = None,
    sdk_path: str | os.PathLike[str] | None = None,
    login_method: str | None = None,
    user_info_method: str | None = None,
    constructor_kwargs: str | Mapping[str, Any] | None = None,
) -> ExternalSdkAuthenticator:
    """Build an adapter from runtime-only SDK configuration.

    Every argument has a corresponding ``AUTH_SDK_*`` environment variable.
    Module and factory names are intentionally required so no concrete SDK is
    embedded in the repository.
    """

    resolved_module = module_name or os.environ.get("AUTH_SDK_MODULE")
    resolved_factory = factory_name or os.environ.get("AUTH_SDK_FACTORY")
    resolved_login_method = login_method or os.environ.get("AUTH_SDK_LOGIN_METHOD")
    resolved_user_info_method = user_info_method or os.environ.get(
        "AUTH_SDK_USER_INFO_METHOD"
    )
    if not resolved_module or not resolved_factory:
        raise RuntimeError(
            "未配置外部认证 SDK；请设置 AUTH_SDK_MODULE 和 AUTH_SDK_FACTORY，"
            "或通过命令行参数传入。"
        )
    if not resolved_login_method or not resolved_user_info_method:
        raise RuntimeError(
            "未配置外部认证方法；请设置 AUTH_SDK_LOGIN_METHOD 和 "
            "AUTH_SDK_USER_INFO_METHOD，或通过命令行参数传入。"
        )

    module = _load_external_module(
        resolved_module,
        sdk_path or os.environ.get("AUTH_SDK_PATH"),
    )
    factory = getattr(module, resolved_factory, None)
    if not callable(factory):
        raise TypeError(
            f"外部认证 SDK 模块没有可调用工厂：{resolved_factory}"
        )

    kwargs = _parse_constructor_kwargs(constructor_kwargs)
    return ExternalSdkAuthenticator(
        lambda: factory(**kwargs),
        login_method=resolved_login_method,
        user_info_method=resolved_user_info_method,
    )
