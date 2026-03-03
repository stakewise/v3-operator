"""
Monkey-patches for web3.py internals.

Tracks evicted aiohttp sessions so they can be force-closed at shutdown.
Workaround until https://github.com/ethereum/web3.py/pull/3805 is released.
"""

from aiohttp import ClientSession
from web3._utils.http_session_manager import HTTPSessionManager

_pending_evicted_sessions: set[ClientSession] = set()

# pylint: disable-next=protected-access
_original_async_close_evicted = HTTPSessionManager._async_close_evicted_sessions


async def _patched_async_close_evicted_sessions(
    self: HTTPSessionManager,
    timeout: float,
    evicted_sessions: list[ClientSession],
) -> None:
    _pending_evicted_sessions.update(evicted_sessions)
    try:
        await _original_async_close_evicted(self, timeout, evicted_sessions)
    finally:
        _pending_evicted_sessions.difference_update(evicted_sessions)


# pylint: disable-next=protected-access
HTTPSessionManager._async_close_evicted_sessions = (  # type: ignore[method-assign]
    _patched_async_close_evicted_sessions
)


async def close_evicted_sessions() -> None:
    """Force-close any evicted sessions still waiting in background tasks."""
    while _pending_evicted_sessions:
        session = _pending_evicted_sessions.pop()
        if not session.closed:
            await session.close()
