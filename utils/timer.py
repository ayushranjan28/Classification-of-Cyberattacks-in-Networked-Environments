"""
Timer and memory tracking utilities for model evaluation.
"""
import time
import os
import psutil
from functools import wraps
from utils.logger import get_logger

log = get_logger(__name__)


class Timer:
    """Context manager for timing code blocks."""
    def __init__(self, label: str = ""):
        self.label = label
        self.elapsed = 0.0

    def __enter__(self):
        self.start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.elapsed = time.perf_counter() - self.start
        if self.label:
            log.info(f"{self.label}: {self.elapsed:.2f}s")


def get_memory_usage_mb() -> float:
    """Get current process memory usage in MB."""
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / (1024 * 1024)


def track_resources(func):
    """Decorator to track time and memory for a function."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        mem_before = get_memory_usage_mb()
        start = time.perf_counter()
        result = func(*args, **kwargs)
        elapsed = time.perf_counter() - start
        mem_after = get_memory_usage_mb()
        log.info(
            f"📊 {func.__name__}: {elapsed:.2f}s, "
            f"Memory: {mem_before:.1f}MB → {mem_after:.1f}MB "
            f"(Δ{mem_after - mem_before:+.1f}MB)"
        )
        return result
    return wrapper
