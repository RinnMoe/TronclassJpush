"""Business-event boundary for the JPush MVP."""

from __future__ import annotations

from jpush_monitor import ROLLCALL_EVENT_TYPES, JPushEvent


def handle_push_event(event: JPushEvent) -> None:
    """Print an event and deliberately do not answer any rollcall.

    Actual number/radar/QR response logic is intentionally out of scope for
    this project. This function is the only boundary that future business
    handlers need to replace.
    """

    if event.event_type in ROLLCALL_EVENT_TYPES:
        print(
            "[placeholder] 收到签到事件 "
            f"{event.event_type}，course_id={event.course_id!r}，"
            f"rollcall_id={event.rollcall_id!r}；未执行签到应答。"
        )
        return

    event_name = event.event_type or "UNKNOWN"
    print(f"[ignored] 收到非签到 JPush 事件 {event_name}。")
