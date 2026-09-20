from __future__ import annotations

import json
import struct

from jpush.models import Credentials
from jpush.sis import build_sis_request
from jpush.store import FileStore, MemoryStore


def test_build_sis_request() -> None:
    payload = build_sis_request("appkey123", "2.1.0", 0x1_0000_0005)
    assert len(payload) == 128
    assert struct.unpack_from(">H", payload)[0] == 128
    assert payload[2:8] == b"UFwifi"
    assert struct.unpack_from(">I", payload, 34)[0] == 0
    assert struct.unpack_from(">I", payload, 38)[0] == 5
    assert payload[42:51] == b"appkey123"
    assert payload[92:97] == b"2.1.0"


def test_file_and_memory_store(tmp_path) -> None:
    credentials = Credentials(
        juid=0x99,
        password="pw",
        reg_id="REGID",
        udid="udid",
        android_id="android",
    )
    store = FileStore(tmp_path / "nested" / "creds.json")
    assert store.load() is None
    store.save(credentials)
    assert store.load() == credentials
    assert json.loads((tmp_path / "nested" / "creds.json").read_text())[
        "reg_id"
    ] == "REGID"

    memory = MemoryStore()
    assert memory.load() is None
    memory.save(credentials)
    assert memory.load() == credentials
