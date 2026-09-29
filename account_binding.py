"""Resolve the authenticated account's official JPush binding values."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit


class AccountBindingError(RuntimeError):
    """The authenticated session could not be exchanged for account bindings."""


@dataclass(frozen=True)
class AccountBindingConfig:
    """The service-side identity settings used by the mobile client."""

    identity_base_url: str
    realm: str
    client_id: str
    redirect_uri: str
    org_id: int
    service_host: str
    timeout: float = 20.0
    max_redirects: int = 12

    @classmethod
    def tronclass_demo(cls) -> AccountBindingConfig:
        return cls(
            identity_base_url="https://identity.chd.edu.cn",
            realm="chd",
            client_id="tronclass-app",
            redirect_uri="https://mobile-download.tronclass.com.cn/callback.html",
            org_id=1,
            service_host="course-online.chd.edu.cn",
        )

    @property
    def oidc_auth_url(self) -> str:
        return (
            f"{self.identity_base_url.rstrip('/')}/auth/realms/{self.realm}"
            "/protocol/openid-connect/auth"
        )

    @property
    def oidc_token_url(self) -> str:
        return (
            f"{self.identity_base_url.rstrip('/')}/auth/realms/{self.realm}"
            "/protocol/openid-connect/token"
        )

    @property
    def api_login_url(self) -> str:
        return f"{self.identity_base_url.rstrip('/')}/api/login"

    @property
    def user_tags_url(self) -> str:
        return f"{self.identity_base_url.rstrip('/')}/api/user/tags"


@dataclass(frozen=True)
class JPushBinding:
    """The alias and tags returned by the authenticated service account."""

    alias: str
    tags: tuple[str, ...]


def fetch_jpush_binding(
    session: Any,
    config: AccountBindingConfig | None = None,
) -> JPushBinding:
    """Exchange a CAS-authenticated session and load its official JPush tags.

    ``session`` intentionally remains an external object.  It only needs the
    requests-like ``get``/``post`` methods, so the authentication SDK stays
    outside this project and its concrete implementation is not imported.
    """

    settings = config or AccountBindingConfig.tronclass_demo()
    _require_method(session, "get")
    _require_method(session, "post")

    callback_url = _exchange_for_callback(session, settings)
    code = _callback_code(callback_url)

    token_response = session.post(
        settings.oidc_token_url,
        data={
            "grant_type": "authorization_code",
            "scope": "openid",
            "redirect_uri": settings.redirect_uri,
            "client_id": settings.client_id,
            "code": code,
        },
        headers=_browser_api_headers(),
        timeout=settings.timeout,
    )
    token_body = _response_json(token_response, "OIDC token")
    access_token = token_body.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise AccountBindingError("OIDC token response did not contain access_token")

    login_response = session.post(
        settings.api_login_url,
        params={"login": "access_token"},
        json={"access_token": access_token, "org_id": settings.org_id},
        headers=_browser_api_headers(host=settings.service_host),
        timeout=settings.timeout,
    )
    _response_json(login_response, "service login")
    session_id = _session_id(login_response, session)
    if not session_id:
        raise AccountBindingError("service login response did not contain X-SESSION-ID")

    tags_response = session.get(
        settings.user_tags_url,
        headers={
            **_browser_api_headers(host=settings.service_host),
            "X-SESSION-ID": session_id,
        },
        timeout=settings.timeout,
    )
    binding_body = _response_json(tags_response, "user tags")
    return _parse_binding(binding_body)


def _exchange_for_callback(session: Any, config: AccountBindingConfig) -> str:
    """Follow the mobile OIDC redirect chain without requesting the callback page."""

    current_url = f"{config.oidc_auth_url}?{urlencode({
        'scope': 'openid',
        'response_type': 'code',
        'redirect_uri': config.redirect_uri,
        'client_id': config.client_id,
    })}"
    callback_parts = urlsplit(config.redirect_uri)

    for _ in range(config.max_redirects):
        try:
            response = session.get(
                current_url,
                allow_redirects=False,
                timeout=config.timeout,
            )
        except Exception as exc:
            raise AccountBindingError("OIDC redirect request failed") from exc

        response_url = getattr(response, "url", current_url)
        if _is_callback_url(response_url, callback_parts):
            return response_url

        location = _header(getattr(response, "headers", {}), "Location")
        if not location:
            raise AccountBindingError(
                "OIDC redirect chain ended before the mobile callback"
            )
        current_url = urljoin(response_url, location)
        if _is_callback_url(current_url, callback_parts):
            return current_url

    raise AccountBindingError("OIDC redirect chain exceeded the safety limit")


def _callback_code(callback_url: str) -> str:
    query = parse_qs(urlsplit(callback_url).query)
    if query.get("error"):
        raise AccountBindingError("OIDC authorization was rejected")
    code = query.get("code", [""])[0]
    if not code:
        raise AccountBindingError("OIDC callback did not contain an authorization code")
    return code


def _parse_binding(body: Mapping[str, Any]) -> JPushBinding:
    alias = body.get("alias")
    raw_tags = body.get("tags")
    if not isinstance(alias, str) or not alias:
        raise AccountBindingError("user tags response did not contain alias")
    if not isinstance(raw_tags, list):
        raise AccountBindingError("user tags response did not contain a tags list")

    tags: list[str] = []
    for tag in raw_tags:
        if not isinstance(tag, str) or not tag:
            raise AccountBindingError("user tags response contained an invalid tag")
        if tag not in tags:
            tags.append(tag)
    return JPushBinding(alias=alias, tags=tuple(tags))


def _response_json(response: Any, name: str) -> dict[str, Any]:
    status = getattr(response, "status_code", 0)
    if not isinstance(status, int) or not 200 <= status < 300:
        raise AccountBindingError(f"{name} request failed with HTTP {status}")
    try:
        value = response.json()
    except (AttributeError, TypeError, ValueError):
        try:
            value = json.loads(response.text)
        except (AttributeError, TypeError, ValueError) as exc:
            raise AccountBindingError(f"{name} response was not JSON") from exc
    if not isinstance(value, dict):
        raise AccountBindingError(f"{name} response was not a JSON object")
    return value


def _session_id(response: Any, session: Any) -> str:
    response_headers = getattr(response, "headers", {})
    value = _header(response_headers, "X-SESSION-ID")
    if value:
        return value

    session_headers = getattr(session, "headers", {})
    value = _header(session_headers, "X-SESSION-ID")
    if value:
        return value

    cookies = getattr(session, "cookies", None)
    get_cookie = getattr(cookies, "get", None)
    if callable(get_cookie):
        value = get_cookie("session")
        if isinstance(value, str):
            return value
    return ""


def _browser_api_headers(*, host: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Origin": "http://localhost",
        "Referer": "http://localhost/",
        "User-Agent": (
            "Mozilla/5.0 (Linux; Android 14; Redmi K30 Pro Zoom Edition "
            "Build/UKQ1.240510.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Version/4.0 Chrome/139.0.7258.158 Mobile Safari/537.36 "
            "TronClass/common"
        ),
    }
    if host:
        headers["Host"] = host
    return headers


def _header(headers: Mapping[str, Any], name: str) -> str:
    wanted = name.lower()
    for key, value in headers.items():
        if str(key).lower() == wanted and isinstance(value, str):
            return value
    return ""


def _is_callback_url(url: str, callback_parts: Any) -> bool:
    parts = urlsplit(url)
    return (
        parts.scheme.lower() == callback_parts.scheme.lower()
        and parts.netloc.lower() == callback_parts.netloc.lower()
        and parts.path == callback_parts.path
    )


def _require_method(target: Any, name: str) -> None:
    if not callable(getattr(target, name, None)):
        raise AccountBindingError(
            "external authentication session must provide get/post methods"
        )
