# pylint: disable=protected-access
"""
Patch web3.py to use a session cache that is unique per event loop
and that properly handles closed session connectors.
Fix RuntimeError: Task ... running at ... got Future ... attached to a different loop
"""
import asyncio
import logging
import threading
from typing import Optional

from aiohttp import ClientSession, TCPConnector
from eth_typing import URI
from web3._utils import request
from web3._utils.async_caching import async_lock
from web3._utils.caching import generate_cache_key
from web3._utils.request import (
    DEFAULT_TIMEOUT,
    _async_close_evicted_sessions,
    _async_session_cache,
    _async_session_cache_lock,
    _async_session_pool,
)

logger = logging.getLogger(__name__)


async def async_cache_and_return_session_patched(
    endpoint_uri: URI,
    session: Optional[ClientSession] = None,
) -> ClientSession:
    # cache key should have a unique thread identifier
    cache_key = generate_cache_key(
        f"{threading.get_ident()}{asyncio.get_running_loop()}:{endpoint_uri}"
    )

    evicted_items = None
    async with async_lock(_async_session_pool, _async_session_cache_lock):
        if cache_key not in _async_session_cache:
            if session is None:
                session = ClientSession(
                    raise_for_status=True,
                    connector=TCPConnector(force_close=True, enable_cleanup_closed=True),
                )

            cached_session, evicted_items = _async_session_cache.cache(cache_key, session)

        else:
            # get the cached session
            cached_session = _async_session_cache.get_cache_entry(cache_key)
            session_is_closed = cached_session.closed
            session_loop_is_closed = cached_session._loop.is_closed()

            warning = (
                'Async session was closed'
                if session_is_closed
                else ('Loop was closed for async session' if session_loop_is_closed else None)
            )
            if warning:
                _async_session_cache._data.pop(cache_key)
                if not session_is_closed:
                    # if loop was closed but not the session, close the session
                    await cached_session.close()

                # replace stale session with a new session at the cache key
                _session = ClientSession(
                    raise_for_status=True,
                    connector=TCPConnector(force_close=True, enable_cleanup_closed=True),
                )
                cached_session, evicted_items = _async_session_cache.cache(cache_key, _session)

    if evicted_items is not None:
        # At this point the evicted sessions are already popped out of the cache and
        # just stored in the `evicted_sessions` dict. So we can kick off a future task
        # to close them and it should be safe to pop out of the lock here.
        evicted_sessions = evicted_items.values()
        # Kick off a future task, in a separate thread, to close the evicted
        # sessions. In the case that the cache filled very quickly and some
        # sessions have been evicted before their original request has been made,
        # we set the timer to a bit more than the `DEFAULT_TIMEOUT` for a call. This
        # should make it so that any call from an evicted session can still be made
        # before the session is closed.
        threading.Timer(
            DEFAULT_TIMEOUT + 0.1,
            _async_close_evicted_sessions,
            args=[evicted_sessions],
        ).start()

    return cached_session


request.async_cache_and_return_session = async_cache_and_return_session_patched
