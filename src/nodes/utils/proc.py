from __future__ import annotations

import logging
import signal
import subprocess
import time
from typing import AnyStr

from src.nodes.utils.timeout import Timeout

logger = logging.getLogger(__name__)


def kill_proc(proc: subprocess.Popen[AnyStr], proc_name: str) -> None:
    try:
        if proc.poll() is None:
            try:
                proc.send_signal(signal.SIGINT)
                wait_for_popen(proc, 30)
            except KeyboardInterrupt:
                logger.info(
                    'Trying to close %s process.  Press Ctrl+C 2 more times to force quit',
                    proc_name,
                )
        if proc.poll() is None:
            try:
                proc.terminate()
                wait_for_popen(proc, 10)
            except KeyboardInterrupt:
                logger.info(
                    'Trying to close %s process.  Press Ctrl+C 1 more times to force quit',
                    proc_name,
                )
        if proc.poll() is None:
            proc.kill()
            wait_for_popen(proc, 2)
    except KeyboardInterrupt:
        proc.kill()


def wait_for_popen(proc: subprocess.Popen[AnyStr], timeout: int = 30) -> None:
    try:
        with Timeout(timeout) as _timeout:
            while proc.poll() is None:
                time.sleep(0.1)
                _timeout.check()
    except Timeout:
        pass
