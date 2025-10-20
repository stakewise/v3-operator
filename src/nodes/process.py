import asyncio
import logging
import time
from pathlib import Path

from eth_typing import BlockNumber, ChecksumAddress

from src.common.consensus import get_chain_finalized_head
from src.common.contracts import VaultContract
from src.common.startup_check import (
    wait_execution_catch_up_consensus,
    wait_for_consensus_node,
    wait_for_execution_node,
)
from src.config.networks import NETWORKS
from src.config.settings import settings
from src.nodes.exceptions import NodeException, NodeFailedToStartError
from src.nodes.lighthouse import update_validator_definitions_file
from src.nodes.typings import StdStreams
from src.nodes.utils.proc import kill_proc
from src.validators.keystores.local import LocalKeystore

logger = logging.getLogger(__name__)


class BaseProcess:
    name: str = ''

    def __init__(
        self,
        program: str | Path,
        args: list[str | Path],
        streams: StdStreams,
    ):
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

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        network: str,
        reth_dir: Path,
        streams: StdStreams,
        prune_receipts_before: BlockNumber,
        era_url: str,
    ):
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
            '--prune.receipts.before',
            str(prune_receipts_before),
        ]

        if era_url:
            args.extend(['--era.enable', '--era.url', era_url])

        super().__init__(program=program, args=args, streams=streams)


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

        super().__init__(program=program, args=args, streams=streams)


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
        super().__init__(program=program, args=args, streams=streams)


class ProcessBuilder:
    """
    Helper class for constructing Execution and Consensus node instances.
    """

    def __init__(self, streams: StdStreams):
        self.streams = streams

    async def get_process(self) -> BaseProcess:
        raise NotImplementedError()


class RethProcessBuilder(ProcessBuilder):
    async def get_process(self) -> RethProcess:
        reth_dir = settings.nodes_dir / 'reth'
        prune_receipts_before = settings.network_config.VALIDATORS_REGISTRY_GENESIS_BLOCK
        era_url = NETWORKS[settings.network].NODE_CONFIG.ERA_URL

        return RethProcess(
            network=settings.network,
            reth_dir=reth_dir,
            streams=self.streams,
            prune_receipts_before=prune_receipts_before,
            era_url=era_url,
        )


class LighthouseProcessBuilder(ProcessBuilder):
    async def get_process(self) -> LighthouseProcess:
        lighthouse_dir = settings.nodes_dir / 'lighthouse'

        # Let Reth create the JWT secret file on first run
        jwt_secret_path = self.get_default_jwt_secret_path()

        return LighthouseProcess(
            network=settings.network,
            lighthouse_dir=lighthouse_dir,
            jwt_secret_path=jwt_secret_path,
            streams=self.streams,
        )

    def get_default_jwt_secret_path(self) -> Path:
        """Returns the default JWT secret path created by Reth."""
        return settings.nodes_dir / 'reth' / 'jwt.hex'


class LighthouseVCProcessBuilder(ProcessBuilder):
    def __init__(
        self,
        streams: StdStreams,
    ):
        super().__init__(streams=streams)
        self.fee_recipient: ChecksumAddress | None = None

    async def get_process(self) -> LighthouseVCProcess:
        # Wait a bit to ensure that the execution and consensus nodes are started
        startup_interval = 10
        await asyncio.sleep(startup_interval)

        # Wait for nodes to be ready
        await wait_for_execution_node()
        await wait_for_consensus_node()

        chain_state = await get_chain_finalized_head()
        await wait_execution_catch_up_consensus(chain_state)

        # Fetch mev escrow address and cache it
        if not self.fee_recipient:
            self.fee_recipient = await self._get_fee_recipient()

        lighthouse_dir = settings.nodes_dir / 'lighthouse'

        validator_definitions_path = (
            settings.nodes_dir / 'lighthouse' / 'validators' / 'validator_definitions.yml'
        )
        # Create the parent directory if it does not exist
        if not validator_definitions_path.parent.exists():
            validator_definitions_path.parent.mkdir(parents=True, exist_ok=True)

        # Usually the validator definitions file is created during `import` command
        # `lighthouse account validator import ...`
        # The problem is the case of per-keystore password files.
        # Natively, Lighthouse import does not support per-keystore password files.
        # So we need to update the validator definitions file manually.

        logger.info('Updating validator definitions file %s...', validator_definitions_path)
        update_validator_definitions_file(
            keystore_files=LocalKeystore.list_keystore_files(),
            output_path=validator_definitions_path,
        )
        # Note on slashing protection.
        # Normally, slashing protection database is updated during `import` command
        # `lighthouse account validator import ...`
        # But since we update the validator definitions file manually, we need to ensure
        # that slashing protection database is updated as well.
        # The option `init_slashing_protection` helps to achieve that.
        # Otherwise, validator client will refuse to start.
        init_slashing_protection = True

        return LighthouseVCProcess(
            network=settings.network,
            lighthouse_dir=lighthouse_dir,
            fee_recipient=self.fee_recipient,
            streams=self.streams,
            init_slashing_protection=init_slashing_protection,
        )

    async def _get_fee_recipient(self) -> ChecksumAddress:
        """
        Fetches the fee recipient address from the vault contract.
        This is used to set the suggested fee recipient for the validator client.
        """
        vault_contract = VaultContract(settings.vault)
        fee_recipient = await vault_contract.mev_escrow()
        return fee_recipient


class ProcessRunner:
    """
    Helper class for running a node process and keeping it alive.
    """

    def __init__(
        self,
        process_builder: ProcessBuilder,
        min_restart_interval: int | None = None,
        start_interval: int = 1,
    ):
        self.process_builder = process_builder
        self.min_restart_interval = min_restart_interval or 60
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
