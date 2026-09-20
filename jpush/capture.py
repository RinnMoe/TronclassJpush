"""Offline inspection helpers for captured JCore frames."""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field

from .codecs import aes_decrypt, derive_jcore_key, md5_hex
from .errors import ProtocolError
from .packet import Reader

ENC_FLAG = 0x80


@dataclass(slots=True)
class Candidate:
    body_offset: int
    key_mode: str
    valid: bool = False
    first_field: str = ""
    parts: list[str] = field(default_factory=list)
    body_hex: str = ""

    @property
    def BodyOffset(self) -> int:
        return self.body_offset

    @property
    def KeyMode(self) -> str:
        return self.key_mode

    @property
    def Valid(self) -> bool:
        return self.valid

    @property
    def FirstField(self) -> str:
        return self.first_field

    @property
    def Parts(self) -> list[str]:
        return self.parts

    @property
    def BodyHex(self) -> str:
        return self.body_hex


@dataclass(slots=True)
class FrameInfo:
    length: int
    version: int
    command: int
    encrypted: bool
    seed: int
    juid: int
    candidates: list[Candidate] = field(default_factory=list)

    @property
    def Length(self) -> int:
        return self.length

    @property
    def Version(self) -> int:
        return self.version

    @property
    def Command(self) -> int:
        return self.command

    @property
    def Encrypted(self) -> bool:
        return self.encrypted

    @property
    def Seed(self) -> int:
        return self.seed

    @property
    def JUID(self) -> int:
        return self.juid

    @property
    def Candidates(self) -> list[Candidate]:
        return self.candidates


def try_decrypt_seed(frame: bytes, offset: int, seed: int) -> str:
    if offset < 0 or offset >= len(frame):
        return ""
    try:
        decrypted = aes_decrypt(derive_jcore_key(seed), frame[offset:])
    except (ProtocolError, ValueError):
        return ""
    return decrypted.hex()


def decode_register_response(body_hex: str) -> list[str]:
    try:
        body = bytes.fromhex(body_hex)
    except ValueError:
        return ["(bad hex)"]
    reader = Reader(body)
    output = [
        f"code        = {reader.int2()}",
        f"juid        = {reader.long8()}",
        f"password    = {_quote(reader.tlv2())}",
        f"regId       = {_quote(reader.tlv2())}",
    ]
    output.append(f"trailing    = {body[reader.pos:].hex()}")
    return output


def decode_ios_register_body(body_hex: str) -> list[str]:
    try:
        body = bytes.fromhex(body_hex)
    except ValueError:
        return ["(bad hex)"]
    reader = Reader(body)
    output: list[str] = []

    def string_field(label: str) -> None:
        output.append(f"{label:<13} = {_quote(reader.tlv2())}")

    def int_field(label: str) -> None:
        output.append(f"{label:<13} = {reader.int1()}")

    string_field("key")
    string_field("appVersion")
    string_field("clientInfo")
    string_field("deviceToken")
    string_field("advertisingId")
    int_field("buildType")
    int_field("apsType")
    int_field("byte0")
    string_field("extKey")
    output.append(f"{'regBusiness':<13} = {reader.int4()}")
    string_field("accountId")
    if reader.error is not None:
        output.append("(note: fields past this point may be misaligned)")
    return output


def _quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def inspect_frame(frame: bytes) -> FrameInfo:
    if len(frame) < 24:
        raise ValueError(f"frame too short: {len(frame)} bytes (need ≥24)")
    length = struct.unpack_from(">H", frame)[0] & 0x7FFF
    info = FrameInfo(
        length=length,
        version=frame[2],
        command=frame[3],
        encrypted=bool(frame[0] & ENC_FLAG),
        seed=struct.unpack_from(">I", frame, 12)[0],
        juid=struct.unpack_from(">q", frame, 16)[0],
    )
    modes = (
        ("seed/transform", derive_jcore_key(info.seed)),
        ("seed/plain", md5_hex(f"JCKP{info.seed}")),
        ("juid/transform", derive_jcore_key(info.juid)),
        ("juid/plain", md5_hex(f"JCKP{info.juid}")),
    )
    for offset in (24, 20):
        if offset >= len(frame):
            continue
        encrypted_body = frame[offset:]
        for mode, key in modes:
            candidate = Candidate(body_offset=offset, key_mode=mode)
            try:
                decrypted = aes_decrypt(key, encrypted_body)
            except (ProtocolError, ValueError):
                info.candidates.append(candidate)
                continue
            reader = Reader(decrypted)
            candidate.valid = True
            candidate.first_field = reader.tlv2()
            candidate.parts = candidate.first_field.split("$$")
            candidate.body_hex = decrypted.hex()
            info.candidates.append(candidate)
    return info


TryDecryptSeed = try_decrypt_seed
DecodeRegisterResponse = decode_register_response
DecodeIOSRegisterBody = decode_ios_register_body
InspectFrame = inspect_frame
