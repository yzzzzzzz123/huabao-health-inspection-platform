"""Deterministic Asia/Shanghai daily-clock helpers.

Policy selection and publication remain outside this thin module. It only
validates a frozen ``HH:mm`` and calculates the next real wall-clock trigger.
"""

from __future__ import annotations

import re
from datetime import datetime, time, timedelta, timezone


SHANGHAI = timezone(timedelta(hours=8), name="Asia/Shanghai")
TIME_RE = re.compile(r"^(?P<hour>[01][0-9]|2[0-3]):(?P<minute>[0-5][0-9])$")


class ScheduleError(ValueError):
    pass


def parse_daily_time(value: str) -> time:
    match = TIME_RE.fullmatch(value)
    if match is None:
        raise ScheduleError("inspection schedule must be HH:mm")
    return time(int(match.group("hour")), int(match.group("minute")), tzinfo=SHANGHAI)


def next_trigger(value: str, *, after: datetime | None = None) -> datetime:
    wall = parse_daily_time(value)
    current = (after or datetime.now(SHANGHAI)).astimezone(SHANGHAI)
    candidate = current.replace(
        hour=wall.hour,
        minute=wall.minute,
        second=0,
        microsecond=0,
    )
    if candidate <= current:
        candidate += timedelta(days=1)
    return candidate


class InspectionScheduleResolver:
    def next_trigger(self, schedule_time: str, *, after: datetime | None = None) -> datetime:
        return next_trigger(schedule_time, after=after)


__all__ = ["InspectionScheduleResolver", "ScheduleError", "next_trigger", "parse_daily_time"]
