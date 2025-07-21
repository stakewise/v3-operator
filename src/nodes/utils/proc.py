from __future__ import annotations

import logging
import signal
import subprocess
import time

from src.nodes.utils.timeout import Timeout

logger = logging.getLogger(__name__)


def kill_proc_list(proc_list: list[subprocess.Popen]) -> None:
    """
    Gracefully shuts down the provided processes
    and waits for their termination in parallel.
    """
    try:
        # Send SIGINT to working processes
        try:
            for proc in proc_list:
                if proc.poll() is None:
                    proc.send_signal(signal.SIGINT)

            wait_for_proc_exit(proc_list, 30)
        except KeyboardInterrupt:
            logger.info('Trying to close process. Press Ctrl+C 2 more times to force quit')

        # Send SIGTERM to working processes
        try:
            for proc in proc_list:
                if proc.poll() is None:
                    proc.terminate()

            wait_for_proc_exit(proc_list, 10)
        except KeyboardInterrupt:
            logger.info('Trying to close process. Press Ctrl+C 1 more times to force quit')

        # Send SIGKILL to working processes
        for proc in proc_list:
            if proc.poll() is None:
                proc.kill()

        wait_for_proc_exit(proc_list, 2)
    except KeyboardInterrupt:
        # Send SIGKILL to working processes
        for proc in proc_list:
            if proc.poll() is None:
                proc.kill()


def wait_for_proc_exit(proc_list: list[subprocess.Popen], timeout: int = 30) -> None:
    try:
        with Timeout(timeout) as _timeout:
            while any(proc.poll() is None for proc in proc_list):
                time.sleep(0.1)
                _timeout.check()
    except Timeout:
        pass
