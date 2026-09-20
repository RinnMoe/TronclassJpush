"""Exceptions raised by :mod:`jpush`."""


class JPushError(Exception):
    """Base exception for client, transport, and protocol failures."""


class ProtocolError(JPushError):
    """The peer sent a malformed or unsupported JCore frame."""


class ConnectionClosedError(JPushError):
    """The client connection ended before the requested operation completed."""
