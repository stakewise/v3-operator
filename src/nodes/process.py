import asyncio
import logging
import time
from pathlib import Path

from eth_typing import ChecksumAddress

from src.common.checks import wait_execution_catch_up_consensus
from src.common.consensus import get_chain_finalized_head
from src.common.contracts import VaultContract
from src.common.startup_check import wait_for_consensus_node, wait_for_execution_node
from src.config.networks import NETWORKS
from src.nodes.exceptions import NodeException, NodeFailedToStartError
from src.nodes.typings import StdStreams
from src.nodes.utils.proc import kill_proc

logger = logging.getLogger(__name__)


class BaseProcess:
    name: str = ''

    def __init__(
        self,
        network: str,
        program: str | Path,
        args: list[str | Path],
        streams: StdStreams,
    ):
        self.network = network
        self.std_streams = streams
        self.program = program
        self.args = args
        self.proc: asyncio.subprocess.Process | None = None  # pylint: disable=no-member

        # Flag to indicate if the process stop was initiated
        # This is used to determine if the process was stopped by the user or exited unexpectedly
        self._is_stopping = False

    async def start(self) -> None:
        if self.proc:
            raise NodeException('Already running')

        if not self.program:
            raise NodeException('Program path is not set')

        command_str = f"{self.program} {' '.join(str(arg) for arg in self.args)}"
        logger.info('Launching %s: %s', self.name, command_str)

        self.proc = await asyncio.create_subprocess_exec(
            self.program,
            *self.args,
            stdin=self.std_streams.stdin,  # nosec
            stdout=self.std_streams.stdout,
            stderr=self.std_streams.stderr,
        )

    @property
    def is_alive(self) -> bool:
        return self.proc is not None and self.proc.returncode is None

    async def stop(self) -> None:
        if not self.proc:
            # Process is not started
            return

        logger.info('Stopping %s...', self.name)
        self._is_stopping = True
        await kill_proc(self.proc)
        logger.info('%s stopped', self.name)

    @property
    def is_stopping(self) -> bool:
        return self._is_stopping


class RethProcess(BaseProcess):
    name = 'Reth'

    def __init__(self, network: str, reth_dir: Path, streams: StdStreams):
        """
        :param network: The network name
        :param reth_dir: The directory where Reth data will be stored
        """
        program = reth_dir / 'reth'

        # Port numbers are set according to Reth's defaults
        args: list[str | Path] = [
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
            *self._build_pruning_options(network),
        ]

        if era_url := NETWORKS[network].NODE_CONFIG.ERA_URL:
            args.extend(['--era.enable', '--era.url', era_url])

        super().__init__(network=network, program=program, args=args, streams=streams)

    def _build_pruning_options(self, network: str) -> list[str]:
        """
        Returns the pruning options for Reth.
        """

        network_config = NETWORKS[network]
        validators_registry_genesis_block = network_config.VALIDATORS_REGISTRY_GENESIS_BLOCK

        return [
            '--prune.receipts.before',
            f'{validators_registry_genesis_block}',
        ]


class LighthouseProcess(BaseProcess):
    name = 'Lighthouse'

    def __init__(
        self, network: str, lighthouse_dir: Path, jwt_secret_path: Path, streams: StdStreams
    ):
        program = lighthouse_dir / 'lighthouse'

        # Port numbers are set according to Lighthouse's defaults
        args: list[str | Path] = [
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

        super().__init__(network=network, program=program, args=args, streams=streams)


class LighthouseVCProcess(BaseProcess):
    name = 'Lighthouse validator client'

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        network: str,
        lighthouse_dir: Path,
        fee_recipient: ChecksumAddress,
        streams: StdStreams,
        init_slashing_protection: bool,
    ):
        program = lighthouse_dir / 'lighthouse'

        args: list[str | Path] = [
            'vc',
            '--network',
            network,
            '--datadir',
            lighthouse_dir,
            '--logfile-dir',
            lighthouse_dir / 'logs',
            '--suggested-fee-recipient',
            fee_recipient,
        ]
        if init_slashing_protection:
            args.append('--init-slashing-protection')
        super().__init__(network=network, program=program, args=args, streams=streams)


class ProcessBuilder:
    """
    Helper class for constructing Execution and Consensus node instances.
    """

    def __init__(self, network: str, data_dir: Path, streams: StdStreams):
        self.network = network
        self.data_dir = data_dir
        self.streams = streams

    @property
    def nodes_dir(self) -> Path:
        return self.data_dir / self.network / 'nodes'

    async def get_process(self) -> BaseProcess:
        raise NotImplementedError()


class RethProcessBuilder(ProcessBuilder):
    async def get_process(self) -> RethProcess:
        reth_dir = self.nodes_dir / 'reth'

        return RethProcess(network=self.network, reth_dir=reth_dir, streams=self.streams)


class LighthouseProcessBuilder(ProcessBuilder):
    async def get_process(self) -> LighthouseProcess:
        lighthouse_dir = self.nodes_dir / 'lighthouse'

        # Let Reth create the JWT secret file on first run
        jwt_secret_path = self.get_default_jwt_secret_path()

        return LighthouseProcess(
            network=self.network,
            lighthouse_dir=lighthouse_dir,
            jwt_secret_path=jwt_secret_path,
            streams=self.streams,
        )

    def get_default_jwt_secret_path(self) -> Path:
        """Returns the default JWT secret path created by Reth."""
        return self.nodes_dir / 'reth' / 'jwt.hex'


class LighthouseVCProcessBuilder(ProcessBuilder):
    def __init__(
        self,
        network: str,
        data_dir: Path,
        streams: StdStreams,
        vault_address: ChecksumAddress,
        init_slashing_protection: bool,
    ):
        super().__init__(network=network, data_dir=data_dir, streams=streams)
        self.vault_address = vault_address
        self.fee_recipient: ChecksumAddress | None = None
        self.init_slashing_protection = init_slashing_protection

    async def get_process(self) -> LighthouseVCProcess:
        # Wait for nodes to be ready
        await wait_for_execution_node()
        await wait_for_consensus_node()

        chain_state = await get_chain_finalized_head()
        await wait_execution_catch_up_consensus(chain_state)

        # Fetch mev escrow address and cache it
        if not self.fee_recipient:
            vault_contract = VaultContract(self.vault_address)
            self.fee_recipient = await vault_contract.mev_escrow()

        lighthouse_dir = self.nodes_dir / 'lighthouse'

        return LighthouseVCProcess(
            network=self.network,
            lighthouse_dir=lighthouse_dir,
            fee_recipient=self.fee_recipient,
            streams=self.streams,
            init_slashing_protection=self.init_slashing_protection,
        )


class ProcessRunner:
    """
    Helper class for running a node process and keeping it alive.
    """

    def __init__(
        self, process_builder: ProcessBuilder, min_restart_interval: int, start_interval: int = 1
    ):
        self.process_builder = process_builder
        self.min_restart_interval = min_restart_interval
        self.start_interval = start_interval
        self.process: BaseProcess | None = None
        self.stderr_max_length = 10_000

    @property
    def is_alive(self) -> bool:
        return self.process is not None and self.process.is_alive

    async def run(self) -> None:
        """
        Starts the process and keeps it running.
        """
        self.process = await self.process_builder.get_process()
        await self.process.start()

        # Give the process some time to start
        await asyncio.sleep(self.start_interval)

        # Handle the case when the process could not start
        # Probably the command is incorrect
        if not self.process.is_alive:
            await self._log_stderr()
            raise NodeFailedToStartError(self.process.name)

        last_restart = time.time()

        while True:
            # Read stdout and stderr to prevent blocking
            await self._read_stdout()
            await self._log_stderr()

            # Check if the process was stopped by another task
            if self.process.is_stopping:
                break

            # If the process is not alive, restart it if the minimum restart interval has passed
            if not self.process.is_alive:
                if time.time() - last_restart >= self.min_restart_interval:
                    logger.info('%s is terminated. Restarting...', self.process.name)
                    self.process = await self.process_builder.get_process()
                    await self.process.start()
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

    async def _read_stdout(self) -> None:
        if self.process and self.process.proc and self.process.proc.stdout:
            await self.process.proc.stdout.read()

    async def _log_stderr(self) -> None:
        if self.process and self.process.proc and self.process.proc.stderr:
            stderr = (await self.process.proc.stderr.read()).decode('utf-8', errors='replace')
            if stderr:
                logger.error('%s:\n%s', self.process.name, stderr[: self.stderr_max_length])
