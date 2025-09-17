import asyncio
import logging
from pathlib import Path

import click
from eth_typing import ChecksumAddress
from sw_utils import InterruptHandler

import src
from src.common.checks import wait_execution_catch_up_consensus
from src.common.clients import setup_clients
from src.common.consensus import get_chain_finalized_head
from src.common.execution import WalletTask, update_oracles_cache
from src.common.logging import setup_logging
from src.common.metrics import MetricsTask, metrics, metrics_server
from src.common.migrate import migrate_to_multivault
from src.common.startup_check import startup_checks
from src.common.tasks import BaseTask
from src.common.utils import get_build_version
from src.config.config import OperatorConfig, OperatorConfigException
from src.config.settings import ValidatorsRegistrationMode, settings
from src.exits.tasks import ExitSignatureTask
from src.harvest.tasks import HarvestTask
from src.reward_splitter.tasks import SplitRewardTask
from src.validators.database import NetworkValidatorCrud, VaultCrud, VaultValidatorCrud
from src.validators.execution import scan_validators_events
from src.validators.keystores.base import BaseKeystore
from src.validators.keystores.load import load_keystore
from src.validators.relayer import RelayerClient
from src.validators.tasks import ValidatorRegistrationSubtask, load_genesis_validators
from src.withdrawals.tasks import ValidatorWithdrawalSubtask

logger = logging.getLogger(__name__)


async def start_base() -> None:
    """Bootstrap operator service and start periodic tasks."""
    setup_logging()
    setup_sentry()
    await setup_clients()

    log_start()

    if not settings.skip_startup_checks:
        await startup_checks()

    if settings.enable_metrics:
        await metrics_server()

    NetworkValidatorCrud().setup()
    VaultValidatorCrud().setup()
    VaultCrud().setup()

    # load network validators from ipfs dump
    await load_genesis_validators()

    keystore: BaseKeystore | None = None
    relayer: RelayerClient | None = None

    if settings.validators_registration_mode == ValidatorsRegistrationMode.AUTO:
        keystore = await load_keystore()
    else:
        relayer = RelayerClient()

    # start operator tasks
    chain_state = await get_chain_finalized_head()
    await wait_execution_catch_up_consensus(chain_state)

    VaultCrud().save_vaults(settings.vaults)
    logger.info('Syncing validator events...')
    await scan_validators_events(chain_state.block_number, is_startup=True)

    logger.info('Updating oracles cache...')
    await update_oracles_cache()

    if settings.validators_registration_mode == ValidatorsRegistrationMode.API:
        logger.info('Starting api mode')

    logger.info('Started operator service')
    metrics.service_started.labels(network=settings.network).set(1)
    with InterruptHandler() as interrupt_handler:
        tasks = [
            ValidatorTask(
                keystore=keystore,
                relayer=relayer,
            ).run(interrupt_handler),
            ExitSignatureTask(
                keystore=keystore,
            ).run(interrupt_handler),
            MetricsTask().run(interrupt_handler),
            WalletTask().run(interrupt_handler),
        ]
        if settings.harvest_vault:
            tasks.append(HarvestTask().run(interrupt_handler))
        if settings.claim_fee_splitter:
            tasks.append(SplitRewardTask().run(interrupt_handler))

        await asyncio.gather(*tasks)


class ValidatorTask(BaseTask):
    def __init__(
        self,
        keystore: BaseKeystore | None,
        relayer: RelayerClient | None,
    ):
        self.validator_registration_subtask = ValidatorRegistrationSubtask(
            keystore=keystore,
            relayer=relayer,
        )
        self.validator_withdrawal_subtask = ValidatorWithdrawalSubtask(relayer)

    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        chain_head = await get_chain_finalized_head()
        await wait_execution_catch_up_consensus(
            chain_head=chain_head, interrupt_handler=interrupt_handler
        )
        await scan_validators_events(block_number=chain_head.block_number, is_startup=False)
        subtasks = [
            self.validator_registration_subtask.process(),
        ]
        if not settings.disable_withdrawals:
            subtasks.append(self.validator_withdrawal_subtask.process(chain_head))
        await asyncio.gather(*subtasks)


def log_start() -> None:
    build = get_build_version()
    start_str = 'Starting operator service'

    if build:
        logger.info('%s, version %s, build %s', start_str, src.__version__, build)
    else:
        logger.info('%s, version %s', start_str, src.__version__)


def setup_sentry() -> None:
    if settings.sentry_dsn:
        # pylint: disable-next=import-outside-toplevel
        import sentry_sdk

        sentry_sdk.init(
            settings.sentry_dsn,
            traces_sample_rate=0.1,
            environment=settings.sentry_environment or settings.network,
        )
        sentry_sdk.set_tag('network', settings.network)
        sentry_sdk.set_tag('project_version', src.__version__)


def load_operator_config(
    vaults: list[ChecksumAddress], data_dir: str, network: str | None, no_confirm: bool
) -> OperatorConfig:
    try:
        operator_config = OperatorConfig(Path(data_dir))
        operator_config.load(network=network)
        return operator_config
    except OperatorConfigException as e:
        if not e.can_be_migrated:
            raise click.ClickException(str(e))

        # trying to migrate from single vault setup to multivault
        vault = vaults[0].lower()
        root_dir = Path(data_dir)
        vault_dir = root_dir / vault
        if vault_dir.exists() and not (root_dir / 'config.json').exists():
            if not no_confirm:
                click.confirm(
                    'The data directory structure has been updated. '
                    'Would you like to migrate to the new schema?',
                    default=True,
                )
            migrate_to_multivault(
                vault_dir=vault_dir,
                root_dir=root_dir,
            )
        operator_config = OperatorConfig(Path(data_dir))
        operator_config.load()
        return operator_config
