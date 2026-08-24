import math
import os
from dataclasses import dataclass
from urllib.parse import urlsplit


DEFAULT_ALLOWED_ORIGINS = (
    "http://localhost:5173",
    "http://127.0.0.1:5173",
)
DEFAULT_MAX_CONCURRENT_SCANS = 4
DEFAULT_SCAN_QUEUE_TIMEOUT_SECONDS = 1.0
DEFAULT_RATE_LIMIT_REQUESTS = 30
DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60


def _positive_integer(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    try:
        value = int(raw_value)
    except ValueError as error:
        raise ValueError(f"{name} must be a positive integer") from error

    if value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _positive_finite_number(name: str, default: float) -> float:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    try:
        value = float(raw_value)
    except ValueError as error:
        raise ValueError(
            f"{name} must be a positive finite number"
        ) from error

    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a positive finite number")
    return value


def _normalize_origin(origin: str) -> str:
    normalized = origin.strip().rstrip("/")
    if (
        not normalized
        or "*" in normalized
        or "?" in normalized
        or "#" in normalized
        or any(character.isspace() for character in normalized)
    ):
        raise ValueError("SENTINEL_ALLOWED_ORIGINS contains an invalid origin")

    try:
        parsed = urlsplit(normalized)
        port = parsed.port
    except ValueError as error:
        raise ValueError(
            "SENTINEL_ALLOWED_ORIGINS contains an invalid origin"
        ) from error

    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.netloc.endswith(":")
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("SENTINEL_ALLOWED_ORIGINS contains an invalid origin")

    if port is not None and not 1 <= port <= 65535:
        raise ValueError("SENTINEL_ALLOWED_ORIGINS contains an invalid origin")

    return normalized


def _allowed_origins_from_environment() -> tuple[str, ...]:
    configured = os.getenv("SENTINEL_ALLOWED_ORIGINS")
    if configured is None:
        return DEFAULT_ALLOWED_ORIGINS

    origins: list[str] = []
    for entry in configured.split(","):
        if not entry.strip():
            continue
        origin = _normalize_origin(entry)
        if origin not in origins:
            origins.append(origin)
    return tuple(origins)


@dataclass(frozen=True)
class DeploymentSettings:
    allowed_origins: tuple[str, ...]
    max_concurrent_scans: int
    scan_queue_timeout_seconds: float
    rate_limit_requests: int
    rate_limit_window_seconds: int

    @classmethod
    def from_environment(cls) -> "DeploymentSettings":
        return cls(
            allowed_origins=_allowed_origins_from_environment(),
            max_concurrent_scans=_positive_integer(
                "SENTINEL_MAX_CONCURRENT_SCANS",
                DEFAULT_MAX_CONCURRENT_SCANS,
            ),
            scan_queue_timeout_seconds=_positive_finite_number(
                "SENTINEL_SCAN_QUEUE_TIMEOUT_SECONDS",
                DEFAULT_SCAN_QUEUE_TIMEOUT_SECONDS,
            ),
            rate_limit_requests=_positive_integer(
                "SENTINEL_RATE_LIMIT_REQUESTS",
                DEFAULT_RATE_LIMIT_REQUESTS,
            ),
            rate_limit_window_seconds=_positive_integer(
                "SENTINEL_RATE_LIMIT_WINDOW_SECONDS",
                DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
            ),
        )
