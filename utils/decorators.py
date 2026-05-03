"""
Reusable decorators: retry with back-off, execution timer, rate-limiter.
"""
from __future__ import annotations

import functools
import time
import threading
from typing import Callable, TypeVar, Any
from utils.exceptions import R3ConXError

F = TypeVar("F", bound=Callable[..., Any])


def retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple[type[Exception], ...] = (Exception,),
) -> Callable[[F], F]:
    """
    Retry decorator with exponential back-off.

    Parameters
    ----------
    max_attempts : max number of tries (including first)
    delay        : initial wait in seconds
    backoff      : multiplier applied to delay after each failure
    exceptions   : exception types that trigger a retry
    """
    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            wait = delay
            for attempt in range(1, max_attempts + 1):
                try:
                    return fn(*args, **kwargs)
                except exceptions as exc:
                    if attempt == max_attempts:
                        raise
                    time.sleep(wait)
                    wait *= backoff
        return wrapper  # type: ignore[return-value]
    return decorator


def timed(label: str | None = None) -> Callable[[F], F]:
    """
    Log execution time of the decorated function.
    The elapsed time is stored in the returned result's
    ``__elapsed__`` attribute when the return value is a dict,
    otherwise it is simply printed via the logger.
    """
    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            from utils.logger import log
            tag = label or fn.__qualname__
            t0 = time.perf_counter()
            result = fn(*args, **kwargs)
            elapsed = time.perf_counter() - t0
            log.debug(f"[timer] {tag} finished in {elapsed:.2f}s")
            if isinstance(result, dict):
                result["__elapsed__"] = round(elapsed, 3)
            return result
        return wrapper  # type: ignore[return-value]
    return decorator


class RateLimiter:
    """
    Thread-safe token-bucket rate limiter.

    Usage:
        limiter = RateLimiter(calls=5, period=1.0)   # 5 calls / second

        @limiter
        def api_call(): ...
    """
    def __init__(self, calls: int, period: float) -> None:
        self._calls  = calls
        self._period = period
        self._lock   = threading.Lock()
        self._timestamps: list[float] = []

    def __call__(self, fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with self._lock:
                now = time.monotonic()
                self._timestamps = [t for t in self._timestamps if now - t < self._period]
                if len(self._timestamps) >= self._calls:
                    sleep_for = self._period - (now - self._timestamps[0])
                    if sleep_for > 0:
                        time.sleep(sleep_for)
                self._timestamps.append(time.monotonic())
            return fn(*args, **kwargs)
        return wrapper  # type: ignore[return-value]
