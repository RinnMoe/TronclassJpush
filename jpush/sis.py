"""JPush SIS (Server IP Service) discovery."""

from __future__ import annotations

import json
import socket
import struct
from dataclasses import dataclass, field

DEFAULT_SIS_PORT = 19000
SIS_SEND_LEN = 128
SIS_TIMEOUT = 6.0
FALLBACK_CONN = "im64.jpush.cn:3000"
DEFAULT_SIS_HOSTS = ("s.jpush.cn", "sis.jpush.io", "easytomessage.com", "113.31.17.108")


@dataclass(slots=True)
class SISResponse:
    ips: list[str] = field(default_factory=list)
    op_conns: list[str] = field(default_factory=list)
    ssl_ips: list[str] = field(default_factory=list)
    ssl_op_conns: list[str] = field(default_factory=list)
    udp_report: list[str] = field(default_factory=list)
    user: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> SISResponse:
        def strings(key: str) -> list[str]:
            value = data.get(key, [])
            return [str(item) for item in value] if isinstance(value, list) else []

        return cls(
            ips=strings("ips"),
            op_conns=strings("op_conns"),
            ssl_ips=strings("ssl_ips"),
            ssl_op_conns=strings("ssl_op_conns"),
            udp_report=strings("udp_report"),
            user=str(data.get("user", "")),
        )


def build_sis_request(
    app_key: str, sdk_version: str, juid: int, network_type: str = "wifi"
) -> bytes:
    """Build the fixed 128-byte UDP request used by the Android SDK."""

    buffer = bytearray(SIS_SEND_LEN)
    struct.pack_into(">H", buffer, 0, SIS_SEND_LEN)
    _copy_into(buffer, 2, f"UF{network_type}".encode())
    struct.pack_into(">I", buffer, 34, 0)
    struct.pack_into(">I", buffer, 38, juid & 0x7FFFFFFF)
    if len(app_key) > 50:
        app_key = app_key[:49]
    _copy_into(buffer, 42, app_key.encode("utf-8"))
    _copy_into(buffer, 92, sdk_version.encode("utf-8"))
    struct.pack_into(">I", buffer, 102, 0)
    return bytes(buffer)


def _copy_into(buffer: bytearray, offset: int, value: bytes) -> None:
    end = min(len(buffer), offset + len(value))
    if end > offset:
        buffer[offset:end] = value[: end - offset]


def query_sis(host: str, payload: bytes, timeout: float | None = None) -> SISResponse:
    """Send one SIS datagram and decode its JSON reply."""

    timeout_value = SIS_TIMEOUT if timeout is None else max(0.0, timeout)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout_value)
        sock.sendto(payload, (host, DEFAULT_SIS_PORT))
        body, _ = sock.recvfrom(4096)
    try:
        data = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"sis json: {exc} (body {body!r})") from exc
    if not isinstance(data, dict):
        raise TypeError("sis json: response is not an object")
    return SISResponse.from_dict(data)


# Source-compatible spellings for callers comparing the Go and Python versions.
buildSISRequest = build_sis_request
querySIS = query_sis
