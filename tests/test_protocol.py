from __future__ import annotations

import io
import struct

import pytest

from jpush.capture import (
    decode_ios_register_body,
    decode_register_response,
    inspect_frame,
)
from jpush.client import Config, parse_android_register_key
from jpush.codecs import (
    CMD_ACK,
    CMD_PUSH_MESSAGE,
    CMD_REGISTER,
    CMD_TAG_ALIAS,
    IOS_VERSION_STRING,
    JCORE_453_REG_VERSION,
    JCORE_473_REG_VERSION,
    JHeadCodec,
    aes_decrypt,
    aes_encrypt,
    derive_jcore_key,
    inspect_jcore_register_request,
    jckp_transform,
)
from jpush.errors import ProtocolError
from jpush.models import Ack, LoginParams, Push, RegisterParams
from jpush.packet import Reader, Writer, decode_response_head, read_raw_frame


def enc_int2(value: int) -> bytes:
    return struct.pack(">H", value & 0xFFFF)


def enc_int4(value: int) -> bytes:
    return struct.pack(">I", value & 0xFFFFFFFF)


def enc_long8(value: int) -> bytes:
    return struct.pack(">Q", value & 0xFFFFFFFFFFFFFFFF)


def enc_tlv2(value: str) -> bytes:
    data = value.encode()
    return struct.pack(">H", len(data)) + data


def server_frame(version: int, command: int, rid: int, juid: int, body: bytes) -> bytes:
    total = 20 + len(body)
    return struct.pack(">HBBQQ", total, version, command, rid, juid) + body


def test_writer_primitives_round_trip() -> None:
    writer = Writer()
    writer.int1(0x2A)
    writer.int2(0x0102)
    writer.int4(0x03040506)
    writer.long8(0x0708090A0B0C0D0E)
    writer.tlv2("ab")
    writer.tlv2("")
    writer.fixed_string("x", 4)
    assert bytes(writer.buf).hex() == (
        "2a0102030405060708090a0b0c0d0e00026162000078000000"
    )

    reader = Reader(bytes([200]) + enc_int2(-5) + enc_int4(70000) + enc_long8(1 << 40))
    reader.buf += enc_tlv2("héllo")
    assert reader.int1() == 200
    assert reader.int2() == -5
    assert reader.int4() == 70000
    assert reader.long8() == 1 << 40
    assert reader.tlv2() == "héllo"
    assert reader.error is None


def test_reader_truncation_and_frame_read() -> None:
    reader = Reader(b"\x00")
    assert reader.int2() == 0
    assert reader.error is not None

    body = b"\x00\x00"
    full = server_frame(1, CMD_ACK, 42, 7, body)
    assert read_raw_frame(io.BytesIO(full)) == full
    head = decode_response_head(full[:20])
    assert (head.command, head.rid, head.juid) == (CMD_ACK, 42, 7)

    with pytest.raises(ProtocolError):
        read_raw_frame(io.BytesIO(b"\x00\x10" + b"\x00" * 14))


def test_classic_golden_encodings() -> None:
    codec = JHeadCodec()
    register = codec.encode_register(
        1,
        RegisterParams(apk_version="1.0", client_info="ci"),
    )
    assert register.hex() == (
        "00260700000000000000000100000000000000000000000000000003312e30"
        "00026369020000"
    )
    login = codec.encode_login(
        2,
        0x1122,
        LoginParams(password_md5="abc", client_version=2001000, app_key="key"),
    )
    assert login.hex() == (
        "002b01010000000000000002000000000000000000001122000000000003616263"
        "001e886800036b657902"
    )
    assert codec.encode_heartbeat(3, 0x55, 9).hex() == (
        "001801020000000000000003000000090000000000000055"
    )


def test_classic_decoding() -> None:
    codec = JHeadCodec()
    register_body = (
        enc_int2(0) + enc_long8(0x99) + enc_tlv2("pw") + enc_tlv2("REGID1") + enc_tlv2("dev")
    )
    register = codec.decode(server_frame(7, CMD_REGISTER, 1, 0x99, register_body))
    assert (register.code, register.juid, register.password, register.reg_id, register.device_id) == (
        0,
        0x99,
        "pw",
        "REGID1",
        "dev",
    )

    error = codec.decode(
        server_frame(7, CMD_REGISTER, 1, 0, enc_int2(1005) + enc_tlv2("appkey mismatch"))
    )
    assert (error.code, error.error) == (1005, "appkey mismatch")

    content = '{"link":"example://token?access_token=T"}'
    push = codec.decode(
        server_frame(1, CMD_PUSH_MESSAGE, 7, 42, bytes([5]) + enc_long8(0xABCDEF) + enc_tlv2(content))
    )
    assert isinstance(push, Push)
    assert (push.msg_type, push.msg_id, push.content) == (5, 0xABCDEF, content)
    assert push.fields()["link"].endswith("access_token=T")

    ack = codec.decode(
        server_frame(1, CMD_ACK, 1, 0, bytes([CMD_TAG_ALIAS, 1, 0]) + enc_long8(123))
    )
    assert isinstance(ack, Ack)
    assert (ack.request_command, ack.step, ack.status, ack.stime) == (CMD_TAG_ALIAS, 1, 0, 123)


def test_jcore_crypto_and_capture() -> None:
    assert jckp_transform(5) == 90
    assert jckp_transform(10) == 90
    assert derive_jcore_key(5) == "356c37f300c48f5f56b5b52839067a20"
    key = derive_jcore_key(42)
    for body in (b"", b"x", b"a 16-byte block!", b"z" * 100):
        encrypted = aes_encrypt(key, body)
        assert len(encrypted) % 16 == 0
        assert aes_decrypt(key, encrypted) == body

    from jpush import NewJCore473Codec

    codec = NewJCore473Codec()
    frame = codec.encode_register(
        1,
        RegisterParams(key="deviceid$$ $$com.example.app$$0123456789abcdef01234567"),
    )
    info = inspect_frame(frame)
    assert info.command == 0
    assert info.encrypted is True
    assert len(info.candidates) == 8
    assert any(candidate.valid and candidate.body_offset == 24 for candidate in info.candidates)


def test_jcore_reg_versions_and_client_info() -> None:
    from jpush import NewJCore453Codec, NewJCore473Codec

    assert JCORE_453_REG_VERSION == 263427
    assert JCORE_473_REG_VERSION == 263939
    config = Config(app_key="key", device_model="Test")
    assert NewJCore453Codec().default_client_info(config).split("$$")[5] == "263427"
    assert NewJCore473Codec().default_client_info(config).split("$$")[5] == "263939"


def test_android_register_key_and_key_ext() -> None:
    key = "$$".join(  # noqa: FLY002
        ("abc", " ", "com.wisdomgarden.trpc", "15126da3dc13d1cbe847512b")
    )
    assert parse_android_register_key(key) == (
        "abc",
        " ",
        "com.wisdomgarden.trpc",
        "15126da3dc13d1cbe847512b",
    )
    from jpush import Client, NewJCore453Codec
    client = Client(
        Config(
            app_key="15126da3dc13d1cbe847512b",
            package_name="com.wisdomgarden.trpc",
            codec=NewJCore453Codec(),
        )
    )
    client.credentials.udid = "abc"
    client.credentials.android_id = "android-id"
    params = client.build_register_params()
    assert params.key == "android-id$$ $$com.wisdomgarden.trpc$$15126da3dc13d1cbe847512b"
    assert params.key_ext.split("$$") == ["0", client.credentials.udid, " ",
                                           client.credentials.android_id, " ", " "]


def test_jcore_register_request_inspection_matches_wire_fields() -> None:
    from jpush import NewJCore453Codec

    codec = NewJCore453Codec()
    frame = codec.encode_register(
        0x1234,
        RegisterParams(
            key="device$$ $$com.example.app$$appkey",
            apk_version="2.16.0",
            client_info="33$$Pixel 5$$unknown$$1080*2340$$en$$263427$$0$$google$$android$$13&33",
            key_ext="0$$device$$ $$android-id$$ $$ ",
            reg_business=7,
            account_id="account",
        ),
    )
    inspected = codec.inspect_register_request(frame)
    assert inspected["wire_length"] & 0x8000
    assert inspected["length"] == len(frame)
    assert inspected["encrypted"] is True
    assert inspected["version"] == 24
    assert inspected["command"] == CMD_REGISTER
    assert inspected["algorithm"] == 1
    assert inspected["wire_rid"] == 0x0100000000001234
    assert inspected["juid"] == 0
    assert inspected["key"] == "device$$ $$com.example.app$$appkey"
    assert inspected["apk_version"] == "2.16.0"
    assert inspected["android_reserved_byte"] == 0
    assert inspected["key_ext"] == "0$$device$$ $$android-id$$ $$ "
    assert inspected["reg_business"] == 7
    assert inspected["account_id"] == "account"
    assert inspected["trailing_hex"] == ""
    assert inspect_jcore_register_request(frame)["header_hex"] == frame[:24].hex()


def test_jcore453_android_login_body_matches_captured_layout() -> None:
    from jpush import NewJCore453Codec

    codec = NewJCore453Codec()
    juid = 0x123456789
    frame = codec.encode_login(
        0x19B9,
        juid,
        LoginParams(
            password_md5="a" * 32,
            version_string="263427|328194",
            app_key="15126da3dc13d1cbe847512b",
            device_hash="b" * 32,
        ),
    )
    plaintext = aes_decrypt(derive_jcore_key(juid), frame[24:])
    assert plaintext[:4] == b"a\x00\x00\x00"
    assert plaintext[4:6] == b"\x00\x20"
    assert plaintext[38:40] == b"\x00\x0d"
    assert b"263427|328194" in plaintext
    assert plaintext[-5:] == b"CN\x00\x00\x01"
    assert len(plaintext) == 129


def test_jcore_unencrypted_error_response_is_decoded() -> None:
    from jpush import NewJCore453Codec

    codec = NewJCore453Codec()
    response = struct.pack(">HBBQQH", 22, 24, 1, 2, 0x123456789, 1015)
    decoded = codec.decode(response)
    assert decoded.code == 1015


def test_jcore_fixed_wire_vectors_match_go() -> None:
    """Regression vectors emitted by the upstream Go codec with seed=5."""

    from jpush import NewJCore473Codec

    codec = NewJCore473Codec()
    codec.reg_seed = 5
    codec._seed_initialized = True
    frames = {
        "register": codec.encode_register(
            1,
            RegisterParams(
                key="device$$ $$com.example.app$$0123456789abcdef01234567",
                apk_version="1.0",
                client_info="ci",
                key_ext="ext",
                reg_business=7,
                account_id="acct",
            ),
        ),
        "login": codec.encode_login(
            2,
            0x99,
            LoginParams(
                password_md5="aabb",
                app_key="0123456789abcdef01234567",
                client_version=2001000,
            ),
        ),
        "alias": codec.encode_set_alias(
            3,
            0x99,
            0x1234,
            "ignored",
            '{"platform":"a","op":"set","alias":"x"}',
        ),
        "heartbeat": codec.encode_heartbeat(4, 0x99, 0x1234),
        "ack": codec.encode_push_ack(5, 0x99, 0x1234, 0, 1, 0x555),
    }
    expected = {
        "register": "80681800010000000000000100000005000000000000000094288d37b3279bbce4eea261b46c86aae3669b54baf605136871b848e80dfb4d0b13cf76b4973115f175c1dc9743d9db633c1f1384d813e288e56db2a20e1ebb7c82c21d5ae422223621943c38fa9925",
        "login": "804818010100000000000002000000000000000000000099bad7cc2c1cd96fb172a8ab41e8ef3b29994fa0ad007c5ca8f2107d92d6219dbcaac00fde97f1f0eb5e79753f81cd21c7",
        "alias": "8048021d0100000000000003000012340000000000000099a2189d5ae254c8e3e6ada42cc7a9564304a83077c957193b78cc30320a46512555594840013792861b080ece80783048",
        "heartbeat": "802818020100000000000004000000000000000000000099f9e5d7b0e833cee53e42050e862a4c8c",
        "ack": "80281804010000000000000500000000000000000000009950463aca3db21fbd3f88578a1d16ef90",
    }
    assert {name: frame.hex() for name, frame in frames.items()} == expected


def test_ios_login_body_layout() -> None:
    from jpush import NewJCore473CodecIOS

    codec = NewJCore473CodecIOS()
    password_md5 = "a" * 32
    device_hash = "b" * 32
    app_key = "0123456789abcdef01234567"
    encoded = codec.encode_login(
        2,
        88500094127,
        LoginParams(
            password_md5=password_md5,
            version_string=IOS_VERSION_STRING,
            app_key=app_key,
            device_hash=device_hash,
        ),
    )
    body = aes_decrypt(derive_jcore_key(88500094127), encoded[24:])
    assert len(body) == 128
    reader = Reader(body)
    assert (reader.int1(), reader.int1(), reader.int2()) == (0x69, 0, 0)
    assert reader.tlv2() == password_md5
    assert reader.tlv2() == IOS_VERSION_STRING
    assert reader.tlv2() == app_key
    assert (reader.int1(), reader.int4(), reader.int1()) == (1, 1, 0)
    assert reader.tlv2() == device_hash
    assert (reader.int1(), reader.int4(), reader.error) == (0, 0, None)


def test_capture_field_rendering() -> None:
    response_hex = (
        enc_int2(0) + enc_long8(0x99) + enc_tlv2("pw") + enc_tlv2("REGID")
    ).hex()
    lines = decode_register_response(response_hex)
    assert 'password    = "pw"' in lines
    assert 'regId       = "REGID"' in lines

    body = b"".join(
        (
            enc_tlv2("key"),
            enc_tlv2("1.0"),
            enc_tlv2("ci"),
            enc_tlv2("$$"),
            enc_tlv2(" "),
            bytes([2, 255, 1]),
            enc_tlv2("ext"),
            enc_int4(0),
            enc_tlv2(""),
        )
    )
    assert any(line.startswith("key") for line in decode_ios_register_body(body.hex()))
