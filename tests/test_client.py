from __future__ import annotations

import socket
import struct
import threading

import pytest

from jpush import Client, Config, MemoryStore, NewJCore453Codec, NewJCore473Codec
from jpush.codecs import (
    CMD_ACK,
    CMD_PUSH_MESSAGE,
    CMD_REGISTER,
    CMD_TAG_ALIAS,
    aes_encrypt,
    derive_jcore_key,
)
from jpush.errors import JPushError
from jpush.models import Credentials
from jpush.packet import read_raw_frame


def enc_int2(value: int) -> bytes:
    return struct.pack(">H", value & 0xFFFF)


def enc_int4(value: int) -> bytes:
    return struct.pack(">I", value & 0xFFFFFFFF)


def enc_long8(value: int) -> bytes:
    return struct.pack(">Q", value & 0xFFFFFFFFFFFFFFFF)


def enc_tlv2(value: str) -> bytes:
    encoded = value.encode()
    return struct.pack(">H", len(encoded)) + encoded


def classic_server_frame(command: int, rid: int, juid: int, body: bytes) -> bytes:
    total = 20 + len(body)
    return struct.pack(">HBBQQ", total, 1, command, rid, juid) + body


def jcore_server_frame(command: int, rid: int, juid: int, seed: int, body: bytes) -> bytes:
    encrypted = aes_encrypt(derive_jcore_key(seed), body)
    total = 20 + len(encrypted)
    output = bytearray(total)
    output[0] = ((total >> 8) & 0xFF) | 0x80
    output[1] = total & 0xFF
    output[2] = 24
    output[3] = command
    output[4] = 1
    struct.pack_into(">H", output, 10, rid & 0xFFFF)
    struct.pack_into(">Q", output, 12, juid & 0xFFFFFFFFFFFFFFFF)
    output[20:] = encrypted
    return bytes(output)


def test_client_classic_round_trip() -> None:
    server, client_socket = socket.socketpair()
    push_content = '{"link":"example://token?access_token=TOK123"}'
    errors: list[BaseException] = []

    def server_loop() -> None:
        try:
            register = read_raw_frame(server)
            rid = struct.unpack_from(">Q", register, 4)[0]
            server.sendall(
                classic_server_frame(
                    CMD_REGISTER,
                    rid,
                    0x99,
                    enc_int2(0) + enc_long8(0x99) + enc_tlv2("pw") + enc_tlv2("REGID") + enc_tlv2("dev"),
                )
            )

            login = read_raw_frame(server)
            rid = struct.unpack_from(">Q", login, 4)[0]
            server.sendall(
                classic_server_frame(
                    1,
                    rid,
                    0x99,
                    enc_int2(0) + enc_int4(0x1234) + enc_int2(3) + enc_tlv2("sk") + enc_int4(1700000000),
                )
            )

            alias = read_raw_frame(server)
            rid = struct.unpack_from(">Q", alias, 4)[0]
            server.sendall(
                classic_server_frame(
                    CMD_ACK,
                    rid,
                    0x99,
                    bytes([CMD_TAG_ALIAS, 1, 0]) + enc_long8(1),
                )
            )
            server.sendall(
                classic_server_frame(
                    CMD_PUSH_MESSAGE,
                    999,
                    0x99,
                    bytes([1]) + enc_long8(555) + enc_tlv2(push_content),
                )
            )
            read_raw_frame(server)  # client push ACK
        except Exception as exc:  # noqa: BLE001 - capture server records test failures
            errors.append(exc)
        finally:
            server.close()

    thread = threading.Thread(target=server_loop)
    thread.start()
    client = Client(
        Config(
            app_key="appkey123",
            package_name="com.example.app",
            servers=("fake:3000",),
            heartbeat_interval=3600,
            dial=lambda _address, _timeout: client_socket,
        )
    )
    credentials = client.register(timeout=5)
    assert (credentials.reg_id, credentials.juid) == ("REGID", 0x99)
    client.set_alias("myalias", timeout=5)
    push = client.wait_for_push(timeout=5)
    assert (push.msg_id, push.content) == (555, push_content)
    client.close()
    thread.join(timeout=2)
    assert not errors


def test_client_jcore_round_trip() -> None:
    server, client_socket = socket.socketpair()
    push_content = '{"link":"example://t?access_token=TOK"}'
    errors: list[BaseException] = []

    def server_loop() -> None:
        try:
            register = read_raw_frame(server)
            rid = struct.unpack_from(">H", register, 10)[0]
            seed = struct.unpack_from(">I", register, 12)[0]
            server.sendall(
                jcore_server_frame(
                    CMD_REGISTER,
                    rid,
                    0x99,
                    seed,
                    enc_int2(0) + enc_long8(0x99) + enc_tlv2("pw") + enc_tlv2("REGID"),
                )
            )

            login = read_raw_frame(server)
            rid = struct.unpack_from(">H", login, 10)[0]
            server.sendall(
                jcore_server_frame(
                    1,
                    rid,
                    0x99,
                    0x99,
                    enc_int2(0) + enc_int4(0x1234) + enc_int2(3) + enc_tlv2("sk") + enc_int4(1700000000),
                )
            )

            alias = read_raw_frame(server)
            rid = struct.unpack_from(">H", alias, 10)[0]
            server.sendall(
                jcore_server_frame(
                    CMD_ACK,
                    rid,
                    0x99,
                    0x99,
                    bytes([CMD_TAG_ALIAS, 1, 0]) + enc_long8(1),
                )
            )
            server.sendall(
                jcore_server_frame(
                    CMD_PUSH_MESSAGE,
                    999,
                    0x99,
                    0x99,
                    bytes([1]) + enc_long8(555) + enc_tlv2(push_content),
                )
            )
            read_raw_frame(server)  # client push ACK
        except Exception as exc:  # noqa: BLE001 - capture server records test failures
            errors.append(exc)
        finally:
            server.close()

    thread = threading.Thread(target=server_loop)
    thread.start()
    client = Client(
        Config(
            app_key="appkey123",
            package_name="com.example.app",
            codec=NewJCore473Codec(),
            servers=("fake:3000",),
            heartbeat_interval=3600,
            dial=lambda _address, _timeout: client_socket,
        )
    )
    credentials = client.register(timeout=5)
    assert (credentials.reg_id, credentials.juid) == ("REGID", 0x99)
    client.set_alias("myalias", timeout=5)
    push = client.wait_for_push(timeout=5)
    assert (push.msg_id, push.content) == (555, push_content)
    client.close()
    thread.join(timeout=2)
    assert not errors


def test_reuse_stored_credentials_skips_register() -> None:
    server, client_socket = socket.socketpair()
    errors: list[BaseException] = []

    def server_loop() -> None:
        try:
            login = read_raw_frame(server)
            assert login[3] == 1
            rid = struct.unpack_from(">Q", login, 4)[0]
            server.sendall(
                classic_server_frame(
                    1,
                    rid,
                    0x99,
                    enc_int2(0) + enc_int4(7) + enc_int2(3) + enc_tlv2("sk") + enc_int4(1),
                )
            )
        except Exception as exc:  # noqa: BLE001 - capture server records test failures
            errors.append(exc)
        finally:
            server.close()

    thread = threading.Thread(target=server_loop)
    thread.start()
    client = Client(
        Config(
            app_key="appkey123",
            store=MemoryStore(Credentials(juid=0x99, password="pw", reg_id="REGID")),
            servers=("fake:3000",),
            heartbeat_interval=3600,
            dial=lambda _address, _timeout: client_socket,
        )
    )
    assert client.register(timeout=5).reg_id == "REGID"
    client.close()
    thread.join(timeout=2)
    assert not errors


def test_failed_registration_preserves_identity() -> None:
    server, client_socket = socket.socketpair()
    store = MemoryStore()

    def server_loop() -> None:
        register = read_raw_frame(server)
        rid = struct.unpack_from(">Q", register, 4)[0]
        seed = struct.unpack_from(">I", register, 12)[0]
        server.sendall(
            jcore_server_frame(
                CMD_REGISTER,
                rid,
                0,
                seed,
                enc_int2(1005) + enc_tlv2("rejected"),
            )
        )
        server.close()

    thread = threading.Thread(target=server_loop)
    thread.start()
    first = Client(
        Config(
            app_key="appkey123",
            package_name="com.example.app",
            codec=NewJCore453Codec(),
            store=store,
            servers=("fake:3000",),
            dial=lambda _address, _timeout: client_socket,
        )
    )
    with pytest.raises(JPushError):
        first.register(timeout=5)
    first_identity = (first.credentials.udid, first.credentials.android_id)
    thread.join(timeout=2)
    assert store.credentials is not None

    second = Client(
        Config(
            app_key="appkey123",
            package_name="com.example.app",
            codec=NewJCore453Codec(),
            store=store,
        )
    )
    second_saved = store.load()
    assert second_saved is not None
    assert (second_saved.udid, second_saved.android_id) == first_identity
    second.close()
