"""Generic authentication boundary for the JPush MVP.

The monitor only needs an authenticated context. The concrete SDK module,
factory and method names are loaded from the local ``config.json`` file, so
this repository does not contain campus-specific authentication details.
"""

from __future__ import annotations

import importlib
import json
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

DEFAULT_CONFIG_PATH = Path(__file__).resolve().with_name("config.json")


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
    sdk_path: Path | None = None,
) -> Any:
    if sdk_path is not None:
        path = sdk_path
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


def _load_runtime_config(config_path: Path) -> dict[str, Any]:
    try:
        parsed = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"未找到配置文件：{config_path}；请在项目根目录创建 config.json。"
        ) from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"config.json 不是有效的 JSON：{exc}") from exc
    except UnicodeDecodeError as exc:
        raise RuntimeError("config.json 必须使用 UTF-8 编码。") from exc
    if not isinstance(parsed, dict):
        raise TypeError("config.json 的根节点必须是 JSON 对象。")
    return parsed


def _require_config_string(config: Mapping[str, Any], key: str) -> str:
    value = config.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"config.json 的 auth_sdk.{key} 必须是非空字符串。")
    return value.strip()


def _parse_constructor_kwargs(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise TypeError("config.json 的 auth_sdk.constructor_kwargs 必须是 JSON 对象。")
    return dict(value)


def build_external_authenticator() -> ExternalSdkAuthenticator:
    """Build an adapter from the project-root ``config.json`` file."""

    config_path = DEFAULT_CONFIG_PATH
    config = _load_runtime_config(config_path)
    auth_config = config.get("auth_sdk")
    if not isinstance(auth_config, Mapping):
        raise TypeError("config.json 必须包含 auth_sdk 配置对象。")

    module_name = _require_config_string(auth_config, "module")
    factory_name = _require_config_string(auth_config, "factory")
    login_method = _require_config_string(auth_config, "login_method")
    user_info_method = _require_config_string(auth_config, "user_info_method")
    sdk_path = Path(_require_config_string(auth_config, "path"))
    if not sdk_path.is_absolute():
        sdk_path = (config_path.parent / sdk_path).resolve()

    module = _load_external_module(module_name, sdk_path)
    factory = getattr(module, factory_name, None)
    if not callable(factory):
        raise TypeError(f"外部认证 SDK 模块没有可调用工厂：{factory_name}")

    kwargs = _parse_constructor_kwargs(auth_config.get("constructor_kwargs"))
    return ExternalSdkAuthenticator(
        lambda: factory(**kwargs),
        login_method=login_method,
        user_info_method=user_info_method,
    )
