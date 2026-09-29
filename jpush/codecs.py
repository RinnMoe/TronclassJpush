"""Classic and modern JCore wire codecs."""

from __future__ import annotations

import hashlib
import json
import secrets
import struct
import threading
from typing import TYPE_CHECKING, Protocol

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .errors import ProtocolError
from .models import (
    Ack,
    LoginParams,
    LoginResult,
    Push,
    RegisterParams,
    RegisterResult,
    Response,
)
from .packet import (
    REQUEST_HEAD_LEN,
    RESPONSE_HEAD_LEN,
    Head,
    Reader,
    Writer,
    decode_response_head,
    frame,
)

if TYPE_CHECKING:
    from .client import Config

CMD_REGISTER = 0
CMD_LOGIN = 1
CMD_HEARTBEAT = 2
CMD_PUSH_MESSAGE = 3
CMD_PUSH_RECEIVED = 4
CMD_TAG_ALIAS = 10
CMD_ACK = 19
CMD_TAGS_V2 = 28
CMD_TAG_ALIAS_V2 = 29

VER_REGISTER = 7
VER_LOGIN = 1
VER_HEARTBEAT = 1
VER_PUSH_RECEIVED = 1
VER_TAGS = 1
VER_TAG_ALIAS = 2

PLATFORM_ANDROID_BYTE = 2
IOS_VERSION_STRING = "132096|197632||||"


class Codec(Protocol):
    def default_client_info(self, config: Config) -> str: ...

    def encode_register(self, rid: int, params: RegisterParams) -> bytes: ...

    def encode_login(self, rid: int, juid: int, params: LoginParams) -> bytes: ...

    def encode_set_alias(
        self, rid: int, juid: int, sid: int, app_key: str, action: str
    ) -> bytes: ...

    def encode_set_tags(
        self, rid: int, juid: int, sid: int, app_key: str, action: str
    ) -> bytes: ...

    def encode_heartbeat(self, rid: int, juid: int, sid: int) -> bytes: ...

    def encode_push_ack(
        self, rid: int, juid: int, sid: int, code: int, msg_type: int, msg_id: int
    ) -> bytes: ...

    def decode(self, data: bytes) -> Response: ...


def _decode_code(reader: Reader) -> tuple[int, str]:
    code = reader.int2()
    if code > 0 and reader.remaining() >= 2:
        return code, reader.tlv2()
    return code, ""


def _raise_reader_error(reader: Reader) -> None:
    if reader.error is not None:
        raise reader.error


class JHeadCodec:
    """The classic plaintext JHead + TLV protocol."""

    def default_client_info(self, config: object) -> str:
        model = getattr(config, "device_model", "") or "Pixel 5"
        return "$$".join(("33", model, "unknown", "1080*2340", "en",
                          str(JCORE_473_REG_VERSION), "0", "google",
                          "android", "13&33"))

    def encode_register(self, rid: int, params: RegisterParams) -> bytes:
        writer = Writer()
        writer.tlv2(params.key)
        writer.tlv2(params.apk_version)
        writer.tlv2(params.client_info)
        writer.int1(PLATFORM_ANDROID_BYTE)
        writer.tlv2(params.key_ext)
        return frame(
            Head(request=True, version=VER_REGISTER, command=CMD_REGISTER, rid=rid),
            writer.buf,
        )

    def encode_login(self, rid: int, juid: int, params: LoginParams) -> bytes:
        writer = Writer()
        writer.fixed_string("", 4)
        writer.tlv2(params.password_md5)
        writer.int4(params.client_version)
        writer.tlv2(params.app_key)
        writer.int1(PLATFORM_ANDROID_BYTE)
        return frame(
            Head(
                request=True,
                version=VER_LOGIN,
                command=CMD_LOGIN,
                rid=rid,
                juid=juid,
            ),
            writer.buf,
        )

    def encode_set_alias(
        self, rid: int, juid: int, sid: int, app_key: str, action: str
    ) -> bytes:
        writer = Writer()
        writer.tlv2(app_key)
        writer.tlv2(action)
        return frame(
            Head(
                request=True,
                version=VER_TAG_ALIAS,
                command=CMD_TAG_ALIAS,
                rid=rid,
                sid=sid,
                juid=juid,
            ),
            writer.buf,
        )

    def encode_set_tags(
        self, rid: int, juid: int, sid: int, app_key: str, action: str
    ) -> bytes:
        writer = Writer()
        writer.tlv2(app_key)
        writer.tlv2(action)
        return frame(
            Head(
                request=True,
                version=VER_TAG_ALIAS,
                command=CMD_TAG_ALIAS,
                rid=rid,
                sid=sid,
                juid=juid,
            ),
            writer.buf,
        )

    def encode_heartbeat(self, rid: int, juid: int, sid: int) -> bytes:
        return frame(
            Head(
                request=True,
                version=VER_HEARTBEAT,
                command=CMD_HEARTBEAT,
                rid=rid,
                sid=sid,
                juid=juid,
            )
        )

    def encode_push_ack(
        self, rid: int, juid: int, sid: int, code: int, msg_type: int, msg_id: int
    ) -> bytes:
        writer = Writer()
        writer.int2(code)
        writer.int1(msg_type)
        writer.long8(msg_id)
        return frame(
            Head(
                request=True,
                version=VER_PUSH_RECEIVED,
                command=CMD_PUSH_RECEIVED,
                rid=rid,
                sid=sid,
                juid=juid,
            ),
            writer.buf,
        )

    def decode(self, data: bytes) -> Response:
        if len(data) < RESPONSE_HEAD_LEN:
            raise ProtocolError(f"jpush: frame too short: {len(data)} bytes")
        head = decode_response_head(data[:RESPONSE_HEAD_LEN])
        reader = Reader(data[RESPONSE_HEAD_LEN:])

        if head.command == CMD_REGISTER:
            result = RegisterResult()
            result.code, result.error = _decode_code(reader)
            if result.code == 0:
                result.juid = reader.long8()
                result.password = reader.tlv2()
                result.reg_id = reader.tlv2()
                result.device_id = reader.tlv2()
            elif result.code == 1007 and reader.remaining() >= 2:
                result.error = reader.tlv2()
            _raise_reader_error(reader)
            return result

        if head.command == CMD_LOGIN:
            result = LoginResult()
            result.code, result.error = _decode_code(reader)
            if result.code == 0:
                result.sid = reader.int4()
                result.server_version = reader.int2()
                result.session_key = reader.tlv2()
                result.server_time = reader.int4()
            _raise_reader_error(reader)
            return result

        if head.command == CMD_PUSH_MESSAGE:
            result = Push(
                msg_type=reader.int1(),
                msg_id=reader.long8(),
                content=reader.tlv2(),
            )
            _raise_reader_error(reader)
            return result

        if head.command == CMD_ACK:
            result = Ack(
                request_command=reader.int1(),
                step=reader.int1(),
                status=reader.int1(),
                stime=reader.long8(),
            )
            _raise_reader_error(reader)
            return result

        if head.command == CMD_TAG_ALIAS:
            code, _ = _decode_code(reader)
            _raise_reader_error(reader)
            # Keep the server code in status so Client.set_alias can report it.
            return Ack(request_command=CMD_TAG_ALIAS, status=code)

        raise ProtocolError(f"jpush: unhandled response command {head.command}")

    EncodeRegister = encode_register
    EncodeLogin = encode_login
    EncodeSetAlias = encode_set_alias
    EncodeSetTags = encode_set_tags
    EncodeHeartbeat = encode_heartbeat
    EncodePushAck = encode_push_ack
    Decode = decode


JCORE_VERSION_ANDROID = 24
JCORE_VERSION_IOS = 25
JCORE_ALGO_AES = 1
JCORE_ENC_FLAG = 0x80
JCORE_453_REG_VERSION = (4 << 16) | (5 << 8) | 3
JCORE_473_REG_VERSION = (4 << 16) | (7 << 8) | 3


def version_code(value: str) -> int:
    parts = value.split(".")
    numbers: list[int] = []
    for index in range(3):
        try:
            numbers.append(int(parts[index].strip()))
        except (IndexError, ValueError):
            numbers.append(0)
    return (numbers[0] << 16) | (numbers[1] << 8) | numbers[2]


def md5_hex(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def jckp_transform(value: int) -> int:
    remainder = value % 10
    factors = {
        1: (5, 88),
        2: (23, 15),
        3: (3, 73),
        4: (13, 96),
        5: (17, 49),
        6: (7, 68),
        7: (31, 39),
        8: (29, 41),
        9: (37, 91),
    }
    multiplier, offset = factors.get(remainder, (8, 74))
    return multiplier * value + value % offset


def derive_jcore_key(seed: int) -> str:
    return md5_hex(f"JCKP{jckp_transform(seed)}")


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    count = block_size - (len(data) % block_size)
    return data + bytes([count]) * count


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    count = data[-1]
    if count == 0 or count > len(data):
        raise ProtocolError(f"bad PKCS7 padding {count} for {len(data)} bytes")
    return data[:-count]


def aes_encrypt(key: str, body: bytes) -> bytes:
    key_bytes = key.encode("ascii")
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(key_bytes[:16]))
    encryptor = cipher.encryptor()
    return encryptor.update(pkcs7_pad(body)) + encryptor.finalize()


def aes_decrypt(key: str, encrypted: bytes) -> bytes:
    key_bytes = key.encode("ascii")
    if not encrypted or len(encrypted) % 16:
        raise ProtocolError("ciphertext not a multiple of block size (16)")
    cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(key_bytes[:16]))
    decryptor = cipher.decryptor()
    padded = decryptor.update(encrypted) + decryptor.finalize()
    return pkcs7_unpad(padded)


class JCore4Codec:
    """AES-256-CBC JCore 4.x codec shared by Android and iOS variants."""

    REG_VERSION = JCORE_473_REG_VERSION

    def __init__(self, *, ios: bool = False) -> None:
        self.reg_seed = 0
        self.juid = 0
        self._seed_initialized = False
        self.ios = ios
        self._lock = threading.Lock()

    @classmethod
    def ios_codec(cls) -> JCore4Codec:
        return cls(ios=True)

    def default_client_info(self, config: object) -> str:
        model = getattr(config, "device_model", "") or "Pixel 5"
        return "$$".join(
            (
                "33",
                model,
                "unknown",
                "1080*2340",
                "en",
                str(self.REG_VERSION),
                "0",
                "google",
                "android",
                "13&33",
            )
        )

    def _head_version(self, command: int) -> int:
        if self.ios and command == CMD_REGISTER:
            return JCORE_VERSION_IOS
        if command == CMD_TAGS_V2:
            return VER_TAGS
        if command == CMD_TAG_ALIAS_V2:
            return VER_TAG_ALIAS
        return JCORE_VERSION_ANDROID

    def set_key_juid(self, juid: int) -> None:
        with self._lock:
            self.juid = juid

    def register_seed(self) -> int:
        with self._lock:
            if not self._seed_initialized:
                self.reg_seed = secrets.randbits(24) or 1
                self._seed_initialized = True
            return self.reg_seed

    def _key_seed(self) -> int:
        with self._lock:
            current_juid = self.juid
        if current_juid > 0:
            return current_juid
        return self.register_seed()

    def encode_register(self, rid: int, params: RegisterParams) -> bytes:
        writer = Writer()
        writer.tlv2(params.key)
        writer.tlv2(params.apk_version)
        writer.tlv2(params.client_info)
        if self.ios:
            writer.tlv2(params.device_token)
            writer.tlv2(params.advertising_id)
            writer.int1(params.build_type)
            writer.int1(params.aps_type)
            writer.int1(1)
        else:
            writer.int1(0)
        writer.tlv2(params.key_ext)
        writer.int4(params.reg_business)
        writer.tlv2(params.account_id)
        seed = self.register_seed()
        return self._frame(CMD_REGISTER, rid, 0, seed, seed, bytes(writer.buf))

    def inspect_register_request(self, data: bytes) -> dict[str, object]:
        """Decrypt and describe a register request without exposing credentials."""

        return inspect_jcore_register_request(data, ios=self.ios)

    def encode_login(self, rid: int, juid: int, params: LoginParams) -> bytes:
        self.set_key_juid(juid)
        writer = Writer()
        if self.ios:
            writer.int1(0x69)
            writer.int1(0)
            writer.int2(0)
            writer.tlv2(params.password_md5)
            writer.tlv2(params.version_string)
            writer.tlv2(params.app_key)
            writer.int1(1)
            writer.int4(1)
            writer.int1(0)
            writer.tlv2(params.device_hash)
            writer.int1(0)
            writer.int4(0)
        else:
            writer.fixed_string("", 4)
            writer.tlv2(params.password_md5)
            writer.int4(params.client_version)
            writer.tlv2(params.app_key)
            writer.int1(PLATFORM_ANDROID_BYTE)
        return self._frame(CMD_LOGIN, rid, juid, 0, juid, bytes(writer.buf))

    def encode_set_alias(
        self, rid: int, juid: int, sid: int, app_key: str, action: str
    ) -> bytes:
        writer = Writer()
        writer.tlv2(action)
        return self._frame(CMD_TAG_ALIAS_V2, rid, juid, sid, juid, bytes(writer.buf))

    def encode_set_tags(
        self, rid: int, juid: int, sid: int, app_key: str, action: str
    ) -> bytes:
        writer = Writer()
        writer.tlv2(action)
        return self._frame(CMD_TAGS_V2, rid, juid, sid, juid, bytes(writer.buf))

    def encode_heartbeat(self, rid: int, juid: int, sid: int) -> bytes:
        return self._frame(CMD_HEARTBEAT, rid, juid, 0, juid, b"")

    def encode_push_ack(
        self, rid: int, juid: int, sid: int, code: int, msg_type: int, msg_id: int
    ) -> bytes:
        writer = Writer()
        writer.int2(code)
        writer.int1(msg_type)
        writer.long8(msg_id)
        return self._frame(
            CMD_PUSH_RECEIVED, rid, juid, 0, juid, bytes(writer.buf)
        )

    def _frame(
        self,
        command: int,
        rid: int,
        juid: int,
        head_seed: int,
        key_seed: int,
        body: bytes,
    ) -> bytes:
        writer = Writer()
        writer.int2(0)
        writer.int1(self._head_version(command))
        writer.int1(command)
        writer.long8(rid)
        writer.int4(head_seed)
        writer.long8(juid)
        encrypted = aes_encrypt(derive_jcore_key(key_seed), body)
        full = bytearray(writer.buf)
        full.extend(encrypted)
        total = len(full)
        full[0] = ((total >> 8) & 0xFF) | JCORE_ENC_FLAG
        full[1] = total & 0xFF
        full[4] = JCORE_ALGO_AES
        return bytes(full)

    def decode(self, data: bytes) -> Response:
        if len(data) < RESPONSE_HEAD_LEN:
            raise ProtocolError(f"jpush: frame too short: {len(data)} bytes")
        wire_length = struct.unpack_from(">H", data)[0]
        total = wire_length & 0x7FFF
        command = data[3]
        body_end = total if RESPONSE_HEAD_LEN <= total <= len(data) else len(data)
        encrypted = bool(wire_length & (JCORE_ENC_FLAG << 8))
        body_bytes = data[RESPONSE_HEAD_LEN:body_end]
        body = (
            aes_decrypt(derive_jcore_key(self._key_seed()), body_bytes)
            if encrypted and body_bytes
            else body_bytes
        )
        reader = Reader(body)

        if command == CMD_REGISTER:
            result = RegisterResult(code=reader.int2())
            if result.code == 0:
                result.juid = reader.long8()
                result.password = reader.tlv2()
                result.reg_id = reader.tlv2()
                if reader.remaining() >= 2:
                    result.device_id = reader.tlv2()
            elif result.code > 0 and reader.remaining() >= 2:
                result.error = reader.tlv2()
            _raise_reader_error(reader)
            return result

        if command == CMD_LOGIN:
            result = LoginResult(code=reader.int2())
            if result.code == 0:
                result.sid = reader.int4()
                result.server_version = reader.int2()
                result.session_key = reader.tlv2()
                result.server_time = reader.int4()
            elif result.code > 0 and reader.remaining() >= 2:
                result.error = reader.tlv2()
            _raise_reader_error(reader)
            return result

        if command == CMD_PUSH_MESSAGE:
            result = Push(
                msg_type=reader.int1(),
                msg_id=reader.long8(),
                content=reader.tlv2(),
            )
            _raise_reader_error(reader)
            return result

        if command == CMD_ACK:
            result = Ack(
                request_command=reader.int1(),
                step=reader.int1(),
                status=reader.int1(),
                stime=reader.long8(),
            )
            _raise_reader_error(reader)
            return result

        if command == CMD_TAG_ALIAS_V2:
            payload = reader.tlv2()
            status = 0
            try:
                parsed = json.loads(payload)
                if isinstance(parsed, dict):
                    status = int(parsed.get("code", 0))
            except (TypeError, ValueError):
                status = 0
            _raise_reader_error(reader)
            return Ack(request_command=CMD_TAG_ALIAS_V2, status=status)

        if command == CMD_TAGS_V2:
            payload = reader.tlv2()
            status = 0
            try:
                parsed = json.loads(payload)
                if isinstance(parsed, dict):
                    status = int(parsed.get("code", 0))
            except (TypeError, ValueError):
                status = 0
            _raise_reader_error(reader)
            return Ack(request_command=CMD_TAGS_V2, status=status)

        if command == CMD_TAG_ALIAS:
            result = Ack(request_command=CMD_TAG_ALIAS, status=reader.int2())
            _raise_reader_error(reader)
            return result

        raise ProtocolError(f"jpush: unhandled response command {command}")

    def key(self, seed: int) -> str:
        return derive_jcore_key(seed)

    EncodeRegister = encode_register
    EncodeLogin = encode_login
    EncodeSetAlias = encode_set_alias
    EncodeSetTags = encode_set_tags
    EncodeHeartbeat = encode_heartbeat
    EncodePushAck = encode_push_ack
    Decode = decode


class JCore473Codec(JCore4Codec):
    """AES-256-CBC JCore 4.7.3 Android codec."""

    REG_VERSION = JCORE_473_REG_VERSION


class JCore453Codec(JCore4Codec):
    """AES-256-CBC JCore 4.5.3 Android codec."""

    REG_VERSION = JCORE_453_REG_VERSION

    def encode_login(self, rid: int, juid: int, params: LoginParams) -> bytes:
        """Encode the Android JCore 4.5.3 login body.

        JCore 4.5.3 does not use the shorter 4.7.x-compatible Android body.
        The official capture has an Android marker, the uppercase password
        digest, a ``JCoreVersion|JPushVersionCode`` TLV, and the device hash.
        The trailing flags are fixed protocol fields for this codec revision.
        """

        self.set_key_juid(juid)
        writer = Writer()
        writer.fixed_string("a", 4)
        writer.tlv2(params.password_md5.upper())
        writer.tlv2(params.version_string)
        writer.tlv2(params.app_key)
        writer.int4(0)
        writer.int1(1)
        writer.int1(0x81)
        writer.int1(1)
        writer.tlv2(params.device_hash)
        writer.int4(2)
        writer.fixed_string("CN", 2)
        writer.int1(0)
        writer.int1(0)
        writer.int1(1)
        return self._frame(CMD_LOGIN, rid, juid, 0, juid, bytes(writer.buf))


def inspect_jcore_register_request(data: bytes, *, ios: bool = False) -> dict[str, object]:
    """Return wire/header and plaintext field evidence for a JCore cmd=0 frame."""

    if len(data) < REQUEST_HEAD_LEN:
        raise ProtocolError(f"jpush: register frame too short: {len(data)} bytes")
    wire_length = struct.unpack_from(">H", data, 0)[0]
    total = wire_length & 0x7FFF
    if total < REQUEST_HEAD_LEN or total > len(data):
        raise ProtocolError(
            f"jpush: invalid register frame length {total} for {len(data)} bytes"
        )
    if data[3] != CMD_REGISTER:
        raise ProtocolError(f"jpush: expected register command 0, got {data[3]}")
    # The encrypted flag is the high bit of the two-byte length field.  The
    # algorithm byte uses the low-level value 0x01 separately at offset 4.
    encrypted = bool(wire_length & (JCORE_ENC_FLAG << 8))
    body_bytes = data[REQUEST_HEAD_LEN:total]
    seed = struct.unpack_from(">I", data, 12)[0]
    body = aes_decrypt(derive_jcore_key(seed), body_bytes) if encrypted else body_bytes
    reader = Reader(body)
    fields: dict[str, object] = {
        "wire_length": wire_length,
        "length": total,
        "encrypted": encrypted,
        "version": data[2],
        "command": data[3],
        # The JCore AES algorithm byte is stamped at offset 4 after the
        # rolling rid was written, so this is the wire-visible rid value.
        "wire_rid": struct.unpack_from(">Q", data, 4)[0],
        "seed": seed,
        "algorithm": data[4],
        "header_hex": data[:REQUEST_HEAD_LEN].hex(),
        "juid": struct.unpack_from(">Q", data, 16)[0],
        "ciphertext_length": len(body_bytes),
        "plaintext_length": len(body),
    }
    fields["key"] = reader.tlv2()
    fields["apk_version"] = reader.tlv2()
    fields["client_info"] = reader.tlv2()
    if ios:
        fields["device_token"] = reader.tlv2()
        fields["advertising_id"] = reader.tlv2()
        fields["build_type"] = reader.int1()
        fields["aps_type"] = reader.int1()
        fields["ios_register_flag"] = reader.int1()
    else:
        fields["android_reserved_byte"] = reader.int1()
    fields["key_ext"] = reader.tlv2()
    fields["reg_business"] = reader.int4()
    fields["account_id"] = reader.tlv2()
    fields["trailing_hex"] = body[reader.pos:].hex()
    if reader.error is not None:
        raise reader.error
    return fields


def NewJCore453Codec() -> JCore453Codec:
    return JCore453Codec()


def NewJCore473Codec() -> JCore473Codec:
    return JCore473Codec()


def NewJCore473CodecIOS() -> JCore473Codec:
    return JCore473Codec(ios=True)


# Go-source-compatible names are useful when comparing a Python capture against
# the upstream implementation.
deriveJCoreKey = derive_jcore_key
jckpTransform = jckp_transform
aesEncrypt = aes_encrypt
aesDecrypt = aes_decrypt
