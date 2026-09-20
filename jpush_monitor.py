"""Small JPush event monitor for the receive-only MVP.

Production reception uses the Python implementation of the device-side JCore
client directly. ``JsonLineJPushSource`` remains available only for local
regression feeds. Neither path polls the TronClass API, and neither one
performs a rollcall response.
"""

from __future__ import annotations

import json
import sys
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from jpush import (
    Client,
    FileStore,
    NewJCore473Codec,
    Push,
)
from jpush import Config as JPushClientConfig

ROLLCALL_EVENT_TYPES = frozenset(
    {"NUMBER_ROLLCALL", "RADAR_ROLLCALL", "QRCODE_ROLLCALL"}
)


@dataclass(frozen=True)
class JPushConfig:
    """Public JPush identity copied from the referenced ChangKe APK."""

    app_key: str
    package_name: str
    channel: str

    @classmethod
    def changke_demo(cls) -> JPushConfig:
        return cls(
            app_key="15126da3dc13d1cbe847512b",
            package_name="com.wisdomgarden.trpc",
            channel="developer-default",
        )


@dataclass(frozen=True)
class JPushEvent:
    """Normalized event while preserving the complete decoded payload."""

    event_type: str | None
    course_id: str | None
    rollcall_id: str | None
    raw_payload: Mapping[str, Any]


class PayloadSource(Protocol):
    """Source contract for a direct JPush client or a local test feed."""

    def __iter__(self) -> Iterator[Any]:
        ...


class JsonLineJPushSource:
    """Read one JSON JPush payload per line from a text stream."""

    def __init__(self, stream: Any = None):
        self._stream = stream or sys.stdin

    def __iter__(self) -> Iterator[Any]:
        for line_number, line in enumerate(self._stream, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                yield json.loads(text)
            except json.JSONDecodeError as exc:
                print(f"[invalid] 第 {line_number} 行不是有效 JSON：{exc}")


class PythonJPushSource:
    """Receive pushes through the Python JPush/JCore client in-process."""

    def __init__(
        self,
        config: JPushConfig,
        store_path: str,
        alias: str | None = None,
        servers: Sequence[str] = (),
        register_timeout: float = 30.0,
        initial_backoff: float = 1.0,
        max_backoff: float = 60.0,
    ):
        self._config = config
        self._store_path = store_path
        self._alias = alias
        self._servers = tuple(servers)
        self._register_timeout = register_timeout
        self._initial_backoff = initial_backoff
        self._max_backoff = max_backoff
        self._closed = threading.Event()
        self._client: Client | None = None

    def __iter__(self) -> Iterator[Any]:
        backoff = self._initial_backoff
        try:
            while not self._closed.is_set():
                client = self._new_client()
                self._client = client
                try:
                    credentials = client.register(timeout=self._register_timeout)
                    if self._alias:
                        client.set_alias(self._alias, timeout=self._register_timeout)
                    print(f"JPush 接收连接已就绪：reg_id={credentials.reg_id}")
                    backoff = self._initial_backoff

                    while not self._closed.is_set():
                        try:
                            push = client.wait_for_push(timeout=1.0)
                        except TimeoutError:
                            continue
                        yield self._push_payload(push)
                except Exception as exc:  # noqa: BLE001 - retry transport/library failures
                    if self._closed.is_set():
                        return
                    print(f"[retry] JPush 接收连接失败：{exc}")
                    self._closed.wait(backoff)
                    backoff = min(backoff * 2, self._max_backoff)
                finally:
                    client.close()
                    self._client = None
        finally:
            self.close()

    def close(self) -> None:
        self._closed.set()
        if self._client is not None:
            self._client.close()

    def _new_client(self) -> Client:
        return Client(
            JPushClientConfig(
                app_key=self._config.app_key,
                package_name=self._config.package_name,
                channel=self._config.channel,
                codec=NewJCore473Codec(),
                store=FileStore(self._store_path),
                servers=self._servers,
            )
        )

    @staticmethod
    def _push_payload(push: Push) -> Mapping[str, Any]:
        try:
            return push.fields()
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"JPush content 不是有效对象：{exc}") from exc


def _decode_payload(payload: Any) -> Mapping[str, Any]:
    if isinstance(payload, Mapping):
        return dict(payload)

    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="replace")

    if isinstance(payload, str):
        try:
            decoded = json.loads(payload)
        except json.JSONDecodeError:
            return {"content": payload}
        if isinstance(decoded, Mapping):
            return dict(decoded)
        return {"content": decoded}

    return {"content": payload}


def _walk_values(value: Any, depth: int = 0) -> Iterator[Any]:
    if depth > 6:
        return

    yield value

    if isinstance(value, Mapping):
        for child in value.values():
            yield from _walk_values(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_values(child, depth + 1)
    elif isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith(("{", "[")):
            try:
                yield from _walk_values(json.loads(stripped), depth + 1)
            except json.JSONDecodeError:
                pass


def _field_values(payload: Mapping[str, Any], names: tuple[str, ...]) -> Iterator[str]:
    for value in _walk_values(payload):
        if not isinstance(value, Mapping):
            continue
        for name in names:
            candidate = value.get(name)
            if isinstance(candidate, (str, int, float)):
                text = str(candidate).strip()
                if text:
                    yield text


def _first_field(payload: Mapping[str, Any], names: tuple[str, ...]) -> str | None:
    return next(iter(_field_values(payload, names)), None)


def _event_type(payload: Mapping[str, Any]) -> str | None:
    candidates = [value.upper() for value in _field_values(
        payload,
        ("title", "event", "eventType", "event_type", "type", "message"),
    )]
    for candidate in candidates:
        if candidate in ROLLCALL_EVENT_TYPES:
            return candidate
    return candidates[0] if candidates else None


def parse_jpush_payload(payload: Any) -> JPushEvent:
    """Normalize common JPush/Cordova payload shapes without dropping data."""

    raw_payload = _decode_payload(payload)
    event_type = _event_type(raw_payload)

    course_id = _first_field(
        raw_payload,
        ("acme-course-id", "courseId", "course_id", "courseID"),
    )
    rollcall_id = _first_field(
        raw_payload,
        ("acme-rollcall-id", "rollcallId", "rollcall_id", "rollcallID"),
    )

    return JPushEvent(
        event_type=event_type,
        course_id=course_id,
        rollcall_id=rollcall_id,
        raw_payload=raw_payload,
    )


class JPushMonitor:
    """Dispatch push payloads; no API querying and no business-side answering."""

    def __init__(
        self,
        config: JPushConfig,
        source: Iterable[Any],
        handler: Callable[[JPushEvent], None],
    ):
        self.config = config
        self.source = source
        self.handler = handler

    def run(self) -> None:
        print(
            "JPush 监测已启动："
            f"package={self.config.package_name}，channel={self.config.channel}"
        )
        try:
            for payload in self.source:
                event = parse_jpush_payload(payload)
                summary = {
                    "event": event.event_type,
                    "course_id": event.course_id,
                    "rollcall_id": event.rollcall_id,
                }
                print(json.dumps(summary, ensure_ascii=False))
                self.handler(event)
        finally:
            close = getattr(self.source, "close", None)
            if close is not None:
                close()
