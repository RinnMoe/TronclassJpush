"""JCore framing and the primitive integer/TLV encodings."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from .errors import ProtocolError

REQUEST_HEAD_LEN = 24
RESPONSE_HEAD_LEN = 20
MAX_PACKET_SIZE = 7168


@dataclass(slots=True)
class Head:
    length: int = 0
    version: int = 0
    command: int = 0
    rid: int = 0
    sid: int = 0
    juid: int = 0
    request: bool = False

    def encode(self, body_length: int) -> bytes:
        """Encode a request header with a 24-byte JCore layout."""

        self.length = REQUEST_HEAD_LEN + body_length
        return struct.pack(
            ">HBBQIQ",
            self.length & 0xFFFF,
            self.version & 0xFF,
            self.command & 0xFF,
            self.rid & 0xFFFFFFFFFFFFFFFF,
            self.sid & 0xFFFFFFFF,
            self.juid & 0xFFFFFFFFFFFFFFFF,
        )


def decode_response_head(data: bytes) -> Head:
    if len(data) < RESPONSE_HEAD_LEN:
        raise ProtocolError(f"jpush: short response head: {len(data)} bytes")
    length, version, command, rid, juid = struct.unpack(">HBBQQ", data[:20])
    return Head(
        length=length,
        version=version,
        command=command,
        rid=rid,
        juid=juid,
        request=False,
    )


class Writer:
    """Accumulate the big-endian primitives used by JCore bodies."""

    def __init__(self) -> None:
        self.buf = bytearray()

    def int1(self, value: int) -> None:
        self.buf.append(value & 0xFF)

    def int2(self, value: int) -> None:
        self.buf.extend(struct.pack(">H", value & 0xFFFF))

    def int4(self, value: int) -> None:
        self.buf.extend(struct.pack(">I", value & 0xFFFFFFFF))

    def long8(self, value: int) -> None:
        self.buf.extend(struct.pack(">Q", value & 0xFFFFFFFFFFFFFFFF))

    def tlv2(self, value: str) -> None:
        encoded = value.encode("utf-8")
        if not encoded or len(encoded) > 0xFFFF:
            self.buf.extend(b"\x00\x00")
            return
        self.buf.extend(struct.pack(">H", len(encoded)))
        self.buf.extend(encoded)

    def fixed_string(self, value: str, length: int) -> None:
        encoded = value.encode("utf-8")[:length]
        self.buf.extend(encoded)
        self.buf.extend(b"\x00" * (length - len(encoded)))


class Reader:
    """Cursor over a body; the first underflow is retained as ``error``."""

    def __init__(self, data: bytes | bytearray | memoryview) -> None:
        self.buf = bytes(data)
        self.pos = 0
        self.error: ProtocolError | None = None

    @property
    def err(self) -> ProtocolError | None:
        return self.error

    def _fail(self, what: str) -> None:
        if self.error is None:
            self.error = ProtocolError(
                f"jpush: truncated body reading {what} at offset "
                f"{self.pos}/{len(self.buf)}"
            )

    def remaining(self) -> int:
        return len(self.buf) - self.pos

    def int1(self) -> int:
        if self.pos + 1 > len(self.buf):
            self._fail("int1")
            return 0
        value = self.buf[self.pos]
        self.pos += 1
        return value

    def int2(self) -> int:
        if self.pos + 2 > len(self.buf):
            self._fail("int2")
            return 0
        value = struct.unpack_from(">h", self.buf, self.pos)[0]
        self.pos += 2
        return value

    def int4(self) -> int:
        if self.pos + 4 > len(self.buf):
            self._fail("int4")
            return 0
        value = struct.unpack_from(">i", self.buf, self.pos)[0]
        self.pos += 4
        return value

    def long8(self) -> int:
        if self.pos + 8 > len(self.buf):
            self._fail("long8")
            return 0
        value = struct.unpack_from(">q", self.buf, self.pos)[0]
        self.pos += 8
        return value

    def tlv2(self) -> str:
        if self.pos + 2 > len(self.buf):
            self._fail("tlv2 length")
            return ""
        length = struct.unpack_from(">H", self.buf, self.pos)[0]
        self.pos += 2
        if self.pos + length > len(self.buf):
            self._fail("tlv2 value")
            return ""
        value = self.buf[self.pos : self.pos + length]
        self.pos += length
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError as exc:
            if self.error is None:
                self.error = ProtocolError(f"jpush: invalid UTF-8 TLV: {exc}")
            return value.decode("utf-8", errors="replace")


def frame(head: Head, body: bytes | bytearray | memoryview = b"") -> bytes:
    body_bytes = bytes(body)
    return head.encode(len(body_bytes)) + body_bytes


def _read_once(reader: Any, size: int) -> bytes:
    if hasattr(reader, "recv"):
        return reader.recv(size)
    return reader.read(size)


def read_exact(reader: Any, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = _read_once(reader, remaining)
        if not chunk:
            raise EOFError("unexpected end of stream")
        chunks.append(bytes(chunk))
        remaining -= len(chunk)
    return b"".join(chunks)


def read_raw_frame(reader: Any) -> bytes:
    """Read one length-prefixed server frame from a socket or file-like object."""

    prefix = read_exact(reader, 2)
    total = struct.unpack(">H", prefix)[0] & 0x7FFF
    if total < RESPONSE_HEAD_LEN:
        raise ProtocolError("jpush: frame shorter than response header")
    if total > MAX_PACKET_SIZE:
        raise ProtocolError(
            f"jpush: frame length {total} exceeds max {MAX_PACKET_SIZE}"
        )
    return prefix + read_exact(reader, total - 2)


def ensure_reader_ok(reader: Reader) -> None:
    if reader.error is not None:
        raise reader.error
