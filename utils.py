from __future__ import annotations

import functools
import re
import threading
import time
from datetime import datetime, timezone
from html import escape


def esc(value) -> str:
    """HTML-escape any value. Use for EVERY dynamic string put into HTML."""
    return escape("" if value is None else str(value), quote=True)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


_CTRL = re.compile(r"[\x00-\x1f\x7f]")


def clean(value, limit: int = 160) -> str:
    """Strip control characters and truncate untrusted text (e.g. banners)."""
    text = _CTRL.sub(" ", str(value)).strip()
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def ttl_cache(seconds: float = 300, maxsize: int = 256):
    """Tiny thread-safe TTL cache. Exceptions are never cached."""

    def decorator(fn):
        store: dict = {}
        lock = threading.Lock()

        @functools.wraps(fn)
        def wrapper(*args):
            now = time.monotonic()
            with lock:
                hit = store.get(args)
                if hit and now - hit[0] < seconds:
                    return hit[1]
            value = fn(*args)
            with lock:
                if len(store) >= maxsize:
                    store.pop(next(iter(store)))
                store[args] = (now, value)
            return value

        return wrapper

    return decorator
