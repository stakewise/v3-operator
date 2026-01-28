import asyncio
from typing import Callable


def memoize(func: Callable) -> Callable:
    """
    Helper to memoize both sync and async functions.
    Main usage is for async functions because `functools.cache` won't work with them.
    """
    cache: dict = {}

    async def memoized_async_func(*args, **kwargs):  # type: ignore
        key = (args, frozenset(sorted(kwargs.items())))
        if key in cache:
            return cache[key]
        result = await func(*args, **kwargs)
        cache[key] = result
        return result

    def memoized_sync_func(*args, **kwargs):  # type: ignore
        key = (args, frozenset(sorted(kwargs.items())))
        if key in cache:
            return cache[key]
        result = func(*args, **kwargs)
        cache[key] = result
        return result

    if asyncio.iscoroutinefunction(func):
        return memoized_async_func
    return memoized_sync_func
