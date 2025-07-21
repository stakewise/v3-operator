from __future__ import annotations

import asyncio
import logging
import signal
import subprocess

from src.nodes.utils.timeout import Timeout

logger = logging.getLogger(__name__)


async def kill_proc(proc: subprocess.Popen) -> None:
    """
    Gracefully shuts down the provided process
    and waits for its termination.
    """
    try:
        # Send SIGINT to working processes
        try:
            proc.send_signal(signal.SIGINT)
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)

            await wait_for_proc_exit(proc, 30)
        except KeyboardInterrupt:
            logger.info('Trying to close process. Press Ctrl+C 2 more times to force quit')

        # Send SIGTERM to working processes
        try:
            if proc.poll() is None:
                proc.terminate()

            await wait_for_proc_exit(proc, 10)
        except KeyboardInterrupt:
            logger.info('Trying to close process. Press Ctrl+C 1 more times to force quit')

        # Send SIGKILL to working processes
        if proc.poll() is None:
            proc.kill()

        await wait_for_proc_exit(proc, 2)
    except KeyboardInterrupt:
        # Send SIGKILL to working processes
        if proc.poll() is None:
            proc.kill()


async def wait_for_proc_exit(proc: subprocess.Popen, timeout: int = 30) -> None:
    try:
        with Timeout(timeout) as _timeout:
            while proc.poll() is None:
                await asyncio.sleep(0.1)
                _timeout.check()
    except Timeout:
        pass
