"""A receive-only client for the JPush device-side JCore protocol.

This package is a Python implementation of the protocol and client flow from
``github.com/thibauddavid/jpush-go``.  It is intentionally receive-only: it
does not implement the JPush REST API used to send notifications.
"""

from .client import (
    DEFAULT_APP_VERSION,
    DEFAULT_HEARTBEAT_INTERVAL,
    DEFAULT_SDK_VERSION,
    Client,
    Config,
    New,
    Platform,
    PlatformAndroid,
    PlatformIOS,
)
from .codecs import (
    JCore453Codec,
    JCore473Codec,
    JHeadCodec,
    NewJCore453Codec,
    NewJCore473Codec,
    NewJCore473CodecIOS,
)
from .errors import (
    ConnectionClosedError,
    JPushError,
    ProtocolError,
)
from .models import (
    Ack,
    Credentials,
    LoginParams,
    LoginResult,
    Push,
    RegisterParams,
    RegisterResult,
)
from .store import FileStore, MemoryStore, Store

__all__ = [
    "DEFAULT_APP_VERSION",
    "DEFAULT_HEARTBEAT_INTERVAL",
    "DEFAULT_SDK_VERSION",
    "Ack",
    "Client",
    "Config",
    "ConnectionClosedError",
    "Credentials",
    "FileStore",
    "JCore453Codec",
    "JCore473Codec",
    "JHeadCodec",
    "JPushError",
    "LoginParams",
    "LoginResult",
    "MemoryStore",
    "New",
    "NewJCore453Codec",
    "NewJCore473Codec",
    "NewJCore473CodecIOS",
    "Platform",
    "PlatformAndroid",
    "PlatformIOS",
    "ProtocolError",
    "Push",
    "RegisterParams",
    "RegisterResult",
    "Store",
]
