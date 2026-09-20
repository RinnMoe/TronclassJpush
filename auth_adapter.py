"""Authentication boundary for the JPush MVP.

The monitor only needs an authenticated context. It must not know how an
account is authenticated, where the service lives, or how credentials are
stored. Other campus authentication SDKs can implement ``Authenticator``
without changing the monitor.
"""

from __future__ import annotations

import importlib
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
    """Adapt any external SDK login callable to ``Authenticator``."""

    def __init__(self, authenticate: Callable[[], AuthContext]):
        self._authenticate = authenticate

    def authenticate(self) -> AuthContext:
        return self._authenticate()


class CHUAuthAuthenticator:
    """Demonstration adapter for the external ``CHUAuthSDK`` package."""

    def __init__(self, auth_factory: Callable[[], Any]):
        self._auth_factory = auth_factory

    def authenticate(self) -> AuthContext:
        auth = self._auth_factory()
        session = auth.login_interactive()
        user_info = auth.get_user_info()
        return AuthContext(session=session, user_info=user_info)


def _load_chu_auth_module(sdk_path: str | os.PathLike[str] | None = None) -> Any:
    """Load the demo SDK without putting credentials or service URLs here.

    ``CHUAUTHSDK_PATH`` is the portable override. The explicit local path is
    retained only as the requested demonstration integration for this machine;
    a different SDK can be supplied by implementing ``Authenticator``.
    """

    candidates = []
    if sdk_path:
        candidates.append(Path(sdk_path))

    configured_path = os.environ.get("CHUAUTHSDK_PATH")
    if configured_path:
        candidates.append(Path(configured_path))

    candidates.append(Path(r"E:\Sync\Github\CHUAuthSDK"))

    for candidate in candidates:
        if candidate.is_dir() and str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))

    try:
        return importlib.import_module("CHUAuthSDK")
    except ImportError as exc:
        raise RuntimeError(
            "无法加载 CHUAuthSDK；请安装该 SDK，或设置 CHUAUTHSDK_PATH。"
        ) from exc


def build_chu_authenticator(
    sdk_path: str | os.PathLike[str] | None = None,
) -> CHUAuthAuthenticator:
    """Create the CHUAuthSDK demo adapter.

    The SDK owns the interactive credential flow. No username, password, CAS
    URL, or business base URL is accepted by this project.
    """

    module = _load_chu_auth_module(sdk_path)
    return CHUAuthAuthenticator(
        lambda: module.CHUAuth(headless=True, verbose=True)
    )
