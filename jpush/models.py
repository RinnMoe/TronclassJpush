"""Public data structures shared by the client and wire codecs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import IntEnum
from typing import Any


class Platform(IntEnum):
    """The device platform used in registration metadata."""

    ANDROID = 0
    IOS = 1


PlatformAndroid = Platform.ANDROID
PlatformIOS = Platform.IOS


class Response:
    """Base class for decoded server responses."""

    command: int


@dataclass(slots=True)
class RegisterResult(Response):
    code: int = 0
    error: str = ""
    juid: int = 0
    password: str = ""
    reg_id: str = ""
    device_id: str = ""
    command: int = 0

    # Go-style read-only aliases make porting a small caller straightforward.
    @property
    def Code(self) -> int:
        return self.code

    @property
    def Error(self) -> str:
        return self.error

    @property
    def JUID(self) -> int:
        return self.juid

    @property
    def Password(self) -> str:
        return self.password

    @property
    def RegID(self) -> str:
        return self.reg_id

    @property
    def DeviceID(self) -> str:
        return self.device_id


@dataclass(slots=True)
class LoginResult(Response):
    code: int = 0
    error: str = ""
    sid: int = 0
    server_version: int = 0
    session_key: str = ""
    server_time: int = 0
    command: int = 1

    @property
    def Code(self) -> int:
        return self.code

    @property
    def Error(self) -> str:
        return self.error

    @property
    def SID(self) -> int:
        return self.sid


@dataclass(slots=True)
class Push(Response):
    """An incoming push; ``content`` is the raw ``msgContent`` JSON."""

    msg_type: int = 0
    msg_id: int = 0
    content: str = ""
    command: int = 3

    def fields(self) -> dict[str, Any]:
        """Decode :attr:`content` as a JSON object."""

        value = json.loads(self.content)
        if not isinstance(value, dict):
            raise TypeError("push content JSON is not an object")
        return value

    Fields = fields

    @property
    def MsgType(self) -> int:
        return self.msg_type

    @property
    def MsgID(self) -> int:
        return self.msg_id

    @property
    def Content(self) -> str:
        return self.content


@dataclass(slots=True)
class Ack(Response):
    request_command: int = 0
    step: int = 0
    status: int = 0
    stime: int = 0
    command: int = 19

    @property
    def RequestCommand(self) -> int:
        return self.request_command

    @property
    def Step(self) -> int:
        return self.step

    @property
    def Status(self) -> int:
        return self.status

    @property
    def STime(self) -> int:
        return self.stime


@dataclass(slots=True)
class RegisterParams:
    key: str = ""
    apk_version: str = ""
    client_info: str = ""
    key_ext: str = ""
    reg_business: int = 0
    account_id: str = ""
    device_token: str = ""
    advertising_id: str = ""
    build_type: int = 0
    aps_type: int = 0


@dataclass(slots=True)
class LoginParams:
    password_md5: str = ""
    app_key: str = ""
    client_version: int = 0
    version_string: str = ""
    device_hash: str = ""


@dataclass(slots=True)
class Credentials:
    """Durable registration identity returned by JPush."""

    juid: int = 0
    password: str = ""
    reg_id: str = ""
    device_id: str = ""
    udid: str = ""
    android_id: str = ""
    device_token: str = ""

    def valid(self) -> bool:
        return self.juid != 0 and bool(self.password) and bool(self.reg_id)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "juid": self.juid,
            "password": self.password,
            "reg_id": self.reg_id,
            "device_id": self.device_id,
        }
        if self.udid:
            result["udid"] = self.udid
        if self.android_id:
            result["android_id"] = self.android_id
        if self.device_token:
            result["device_token"] = self.device_token
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Credentials:
        return cls(
            juid=int(data.get("juid", 0)),
            password=str(data.get("password", "")),
            reg_id=str(data.get("reg_id", "")),
            device_id=str(data.get("device_id", "")),
            udid=str(data.get("udid", "")),
            android_id=str(data.get("android_id", "")),
            device_token=str(data.get("device_token", "")),
        )
