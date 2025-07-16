import logging
import subprocess
from pathlib import Path

from src.nodes.exceptions import NodeException
from src.nodes.typings import IO_Any
from src.nodes.utils.proc import kill_proc

logger = logging.getLogger(__name__)


class BaseProcess:
    name: str = ''

    def __init__(
        self,
        stdin: IO_Any = subprocess.PIPE,
        stdout: IO_Any = subprocess.PIPE,
        stderr: IO_Any = subprocess.PIPE,
    ):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.command: list[str | Path] = []
        self.proc: subprocess.Popen | None = None

    def start(self) -> None:
        if self.proc:
            raise NodeException('Already running')

        command_str = ' '.join(str(arg) for arg in self.command)
        logger.info('Launching %s: %s', self.name, command_str)

        self.proc = subprocess.Popen(  # pylint: disable=consider-using-with
            self.command,
            stdin=self.stdin,  # nosec
            stdout=self.stdout,
            stderr=self.stderr,
        )

    def stop(self) -> None:
        if self.proc is None:
            raise NodeException('Not running')

        if self.proc.poll() is None:
            kill_proc(self.proc, self.name)
            self.proc = None

    @property
    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None


class RethProcess(BaseProcess):
    name = 'Reth'

    def __init__(self, network: str, data_dir: Path):
        super().__init__()

        reth_dir = data_dir / network / 'nodes' / 'reth'
        binary_path = reth_dir / 'reth'

        self.command = [
            binary_path,
            'node',
            '--full',
            '--chain',
            network,
            '--datadir',
            reth_dir,
            '--port',
            '30303',
            '--discovery.port',
            '30303',
            '--enable-discv5-discovery',
            '--discovery.v5.port',
            '30304',
            '--http',
            '--http.port',
            '8545',
            '--http.api',
            'all',
            '--log.file.directory',
            reth_dir / 'logs',
            '--max-outbound-peers',
            '25',
            '--max-inbound-peers',
            '25',
            '--authrpc.jwtsecret',
            reth_dir / 'jwt.hex',
        ]
