import logging
import subprocess
from pathlib import Path

from src.config.networks import NETWORKS
from src.nodes.exceptions import NodeException
from src.nodes.typings import IO_Any
from src.nodes.utils.proc import kill_proc_list

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

    @property
    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None


class RethProcess(BaseProcess):
    name = 'Reth'

    def __init__(self, network: str, reth_dir: Path):
        """
        :param network: The network name
        :param reth_dir: The directory where Reth data will be stored
        """
        super().__init__()
        self.reth_dir = reth_dir

        binary_path = reth_dir / 'reth'

        # Port numbers are set according to Reth's defaults
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
            '--max-outbound-peers',
            '25',
            '--max-inbound-peers',
            '25',
            '--log.file.directory',
            reth_dir / 'logs',
            '--nat',
            'upnp',
        ]

        if era_url := NETWORKS[network].NODE_CONFIG.ERA_URL:
            self.command.extend(['--era.enable', '--era.url', era_url])


class LighthouseProcess(BaseProcess):
    name = 'Lighthouse'

    def __init__(self, network: str, lighthouse_dir: Path, jwt_secret_path: Path):
        super().__init__()

        binary_path = lighthouse_dir / 'lighthouse'

        # Port numbers are set according to Lighthouse's defaults
        self.command = [
            binary_path,
            'bn',
            '--network',
            network,
            '--datadir',
            lighthouse_dir,
            '--staking',
            '--validator-monitor-auto',
            '--checkpoint-sync-url',
            NETWORKS[network].NODE_CONFIG.CONSENSUS_CHECKPOINT_SYNC_URL,
            '--port',
            '9000',
            '--quic-port',
            '9001',
            '--http-port',
            '5052',
            '--execution-endpoint',
            'http://127.0.0.1:8551',
            '--execution-jwt',
            jwt_secret_path,
            '--logfile-dir',
            lighthouse_dir / 'logs',
        ]


def shutdown_processes(processes: list[BaseProcess]) -> None:
    """
    Wrapper around `kill_proc_list` accepting `BaseProcess` list
    """
    proc_list = [proc.proc for proc in processes if proc.proc is not None]

    kill_proc_list(proc_list)


class ProcessBuilder:
    """
    Helper class for constructing Execution and Consensus node instances.
    """

    def __init__(self, network: str, data_dir: Path):
        self.network = network
        self.data_dir = data_dir

    @property
    def nodes_dir(self) -> Path:
        return self.data_dir / self.network / 'nodes'

    def get_reth_process(self) -> RethProcess:
        reth_dir = self.nodes_dir / 'reth'

        return RethProcess(network=self.network, reth_dir=reth_dir)

    def get_lighthouse_process(self) -> LighthouseProcess:
        lighthouse_dir = self.nodes_dir / 'lighthouse'

        # Let Reth create the JWT secret file on first run
        jwt_secret_path = self.get_default_jwt_secret_path()

        return LighthouseProcess(
            network=self.network, lighthouse_dir=lighthouse_dir, jwt_secret_path=jwt_secret_path
        )

    def get_default_jwt_secret_path(self) -> Path:
        """Returns the default JWT secret path created by Reth."""
        return self.nodes_dir / 'reth' / 'jwt.hex'
