import asyncio
import logging
import subprocess
import time
from pathlib import Path

from src.config.networks import NETWORKS
from src.nodes.exceptions import NodeException
from src.nodes.typings import IO_Any
from src.nodes.utils.proc import kill_proc

logger = logging.getLogger(__name__)


class BaseProcess:
    name: str = ''

    def __init__(
        self,
        network: str,
        stdin: IO_Any = subprocess.PIPE,
        stdout: IO_Any = subprocess.PIPE,
        stderr: IO_Any = subprocess.PIPE,
    ):
        self.network = network
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

    async def stop(self) -> None:
        if not self.proc:
            # Process is not started
            return

        logger.info('Stopping %s...', self.name)
        await kill_proc(self.proc)

    @property
    def is_stopped(self) -> bool:
        return self.proc is not None and self.proc.poll() is not None


class RethProcess(BaseProcess):
    name = 'Reth'

    def __init__(self, network: str, reth_dir: Path):
        """
        :param network: The network name
        :param reth_dir: The directory where Reth data will be stored
        """
        super().__init__(network=network)
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
            *self.pruning_options,
        ]

        if era_url := NETWORKS[network].NODE_CONFIG.ERA_URL:
            self.command.extend(['--era.enable', '--era.url', era_url])

    @property
    def pruning_options(self) -> list[str]:
        """
        Returns the pruning options for Reth.
        """

        network_config = NETWORKS[self.network]
        validators_registry_genesis_block = network_config.VALIDATORS_REGISTRY_GENESIS_BLOCK

        return [
            '--prune.receipts.before',
            f'{validators_registry_genesis_block}',
        ]


class LighthouseProcess(BaseProcess):
    name = 'Lighthouse'

    def __init__(self, network: str, lighthouse_dir: Path, jwt_secret_path: Path):
        super().__init__(network=network)

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

    def get_process(self) -> BaseProcess:
        raise NotImplementedError()


class RethProcessBuilder(ProcessBuilder):
    def get_process(self) -> RethProcess:
        reth_dir = self.nodes_dir / 'reth'

        return RethProcess(network=self.network, reth_dir=reth_dir)


class LighthouseProcessBuilder(ProcessBuilder):
    def get_process(self) -> LighthouseProcess:
        lighthouse_dir = self.nodes_dir / 'lighthouse'

        # Let Reth create the JWT secret file on first run
        jwt_secret_path = self.get_default_jwt_secret_path()

        return LighthouseProcess(
            network=self.network, lighthouse_dir=lighthouse_dir, jwt_secret_path=jwt_secret_path
        )

    def get_default_jwt_secret_path(self) -> Path:
        """Returns the default JWT secret path created by Reth."""
        return self.nodes_dir / 'reth' / 'jwt.hex'


class ProcessRunner:
    """
    Helper class for running a node process and keeping it alive.
    """

    def __init__(self, process_builder: ProcessBuilder, min_restart_interval: int):
        self.process_builder = process_builder
        self.min_restart_interval = min_restart_interval
        self.process: BaseProcess | None = None

    @property
    def is_alive(self) -> bool:
        return self.process is not None and self.process.is_alive

    async def run(self) -> None:
        """
        Starts the process and keeps it running.
        """
        self.process = self.process_builder.get_process()
        self.process.start()
        last_restart = time.time()

        while True:
            # Check if the process is stopped by another task
            if self.process.is_stopped:
                break

            # If the process is not alive, restart it if the minimum restart interval has passed
            if not self.process.is_alive:
                if time.time() - last_restart >= self.min_restart_interval:
                    logger.info('%s is terminated. Restarting...', self.process.name)
                    self.process = self.process_builder.get_process()
                    self.process.start()
                    last_restart = time.time()
                else:
                    logger.info(
                        '%s is not alive, but waiting for restart interval %d sec to pass...',
                        self.process.name,
                        self.min_restart_interval,
                    )

            await asyncio.sleep(1)

    async def stop(self) -> None:
        if self.process:
            await self.process.stop()
