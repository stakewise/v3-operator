import asyncio
import logging

from sw_utils import EventScanner, InterruptHandler

import src
from src.common.checks import wait_execution_catch_up_consensus
from src.common.consensus import get_chain_finalized_head
from src.common.execution import WalletTask, update_oracles_cache
from src.common.logging import setup_logging
from src.common.metrics import MetricsTask, metrics_server
from src.common.startup_check import startup_checks
from src.common.utils import get_build_version
from src.config.settings import settings
from src.exits.tasks import ExitSignatureTask
from src.harvest.tasks import HarvestTask
from src.validators.database import NetworkValidatorCrud
from src.validators.execution import NetworkValidatorsProcessor
from src.validators.keystores.base import BaseKeystore
from src.validators.keystores.load import load_keystore
from src.validators.relayer import BaseRelayerClient
from src.validators.tasks import ValidatorsTask, load_genesis_validators
from src.validators.tests.local_relayer import create_local_relayer
from src.validators.typings import DepositData, ValidatorsRegistrationMode
from src.validators.utils import load_deposit_data

logger = logging.getLogger(__name__)


async def start_base() -> None:
    setup_logging()
    setup_sentry()
    log_start()

    if not settings.skip_startup_checks:
        await startup_checks()

    NetworkValidatorCrud().setup()

    # load network validators from ipfs dump
    await load_genesis_validators()

    keystore: BaseKeystore | None = None
    deposit_data: DepositData | None = None
    relayer: BaseRelayerClient | None = None

    # load keystore and deposit data
    if settings.validators_registration_mode == ValidatorsRegistrationMode.AUTO:
        keystore = await load_keystore()

        deposit_data = load_deposit_data(settings.vault, settings.deposit_data_file)
        logger.info('Loaded deposit data file %s', settings.deposit_data_file)
    else:
        # todo: replace with actual RelayerClient once Relayer service is ready
        settings.pool_size = 2
        relayer = await create_local_relayer()

    # start operator tasks

    # periodically scan network validator updates
    network_validators_processor = NetworkValidatorsProcessor()
    network_validators_scanner = EventScanner(network_validators_processor)

    logger.info('Syncing network validator events...')
    chain_state = await get_chain_finalized_head()
    await wait_execution_catch_up_consensus(chain_state)
    await network_validators_scanner.process_new_events(chain_state.execution_block)

    logger.info('Updating oracles cache...')
    await update_oracles_cache()

    if settings.validators_registration_mode == ValidatorsRegistrationMode.API:
        logger.info('Starting api mode')

    if settings.enable_metrics:
        await metrics_server()

    logger.info('Started operator service')
    with InterruptHandler() as interrupt_handler:
        tasks = [
            ValidatorsTask(
                keystore=keystore,
                deposit_data=deposit_data,
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

        await asyncio.gather(*tasks)


def log_start() -> None:
    build = get_build_version()
    start_str = 'Starting operator service'

    if build:
        logger.info('%s, version %s, build %s', start_str, src.__version__, build)
    else:
        logger.info('%s, version %s', start_str, src.__version__)


def setup_sentry():
    if settings.sentry_dsn:
        # pylint: disable-next=import-outside-toplevel
        import sentry_sdk

        sentry_sdk.init(
            settings.sentry_dsn,
            traces_sample_rate=0.1,
            environment=settings.sentry_environment or settings.network,
        )
        sentry_sdk.set_tag('network', settings.network)
        sentry_sdk.set_tag('vault', settings.vault)
