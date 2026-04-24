from dataclasses import dataclass, asdict
from enum import Enum
from typing import Callable, Any


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    SKIPPED = "skipped"
    UNKNOWN = "unknown"


@dataclass
class CheckResult:
    check_id: str
    status: Status
    details: str
    raw_data: dict | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["status"] = self.status.value
        if data["raw_data"] is None:
            data["raw_data"] = {}
        return data


def check(**metadata):
    def decorator(func: Callable[[dict], CheckResult]):
        func._check_meta = metadata
        return func
    return decorator
