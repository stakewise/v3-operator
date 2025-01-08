import asyncio
import logging

from sw_utils import EventScanner, InterruptHandler

import src
from src.common.checks import wait_execution_catch_up_consensus
from src.common.clients import setup_clients
from src.common.consensus import get_chain_finalized_head
from src.common.execution import WalletTask, update_oracles_cache
from src.common.logging import setup_logging
from src.common.metrics import MetricsTask, metrics, metrics_server
from src.common.startup_check import startup_checks
from src.common.utils import get_build_version
from src.config.settings import settings
from src.exits.tasks import ExitSignatureTask
from src.harvest.tasks import HarvestTask
from src.validators.database import NetworkValidatorCrud
from src.validators.execution import NetworkValidatorsStartupProcessor
from src.validators.keystores.base import BaseKeystore
from src.validators.keystores.load import load_keystore
from src.validators.relayer import RelayerAdapter, create_relayer_adapter
from src.validators.tasks import ValidatorsTask, load_genesis_validators
from src.validators.typings import DepositData, ValidatorsRegistrationMode
from src.validators.utils import load_deposit_data

logger = logging.getLogger(__name__)


async def start_base() -> None:
    setup_logging()
    setup_sentry()
    await setup_clients()

    log_start()

    if not settings.skip_startup_checks:
        await startup_checks()

    if settings.enable_metrics:
        await metrics_server()

    NetworkValidatorCrud().setup()

    # load network validators from ipfs dump
    await load_genesis_validators()

    keystore: BaseKeystore | None = None
    deposit_data: DepositData | None = None
    relayer_adapter: RelayerAdapter | None = None

    # load keystore and deposit data
    if settings.validators_registration_mode == ValidatorsRegistrationMode.AUTO:
        keystore = await load_keystore()

        deposit_data = load_deposit_data(settings.vault, settings.deposit_data_file)
        logger.info('Loaded deposit data file %s', settings.deposit_data_file)
    else:
        relayer_adapter = create_relayer_adapter()

    # start operator tasks

    # scan network validator updates
    network_validators_startup_processor = NetworkValidatorsStartupProcessor()
    network_validators_scanner = EventScanner(network_validators_startup_processor)

    logger.info('Syncing network validator events...')
    chain_state = await get_chain_finalized_head()
    await wait_execution_catch_up_consensus(chain_state)
    await network_validators_scanner.process_new_events(chain_state.block_number)

    logger.info('Updating oracles cache...')
    await update_oracles_cache()

    if settings.validators_registration_mode == ValidatorsRegistrationMode.API:
        logger.info('Starting api mode')

    logger.info('Started operator service')
    metrics.service_started.set(1)
    with InterruptHandler() as interrupt_handler:
        tasks = [
            ValidatorsTask(
                keystore=keystore,
                deposit_data=deposit_data,
                relayer_adapter=relayer_adapter,
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
        sentry_sdk.set_tag('vault', settings.vault)
        sentry_sdk.set_tag('project_version', src.__version__)
