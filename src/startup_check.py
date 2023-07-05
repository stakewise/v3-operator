import asyncio
import logging
import time
from os import path

from aiohttp import ClientSession, ClientTimeout
from sw_utils import IpfsFetchClient, get_consensus_client, get_execution_client

from src.common.clients import db_client
from src.common.execution import check_hot_wallet_balance, get_oracles
from src.common.utils import count_files_in_folder
from src.common.wallet import hot_wallet
from src.config.settings import settings
from src.validators.execution import check_deposit_data_root
from src.validators.utils import count_deposit_data_non_exited_keys, load_deposit_data

logger = logging.getLogger(__name__)

IPFS_HASH_EXAMPLE = 'QmawUdo17Fvo7xa6ARCUSMV1eoVwPtVuzx8L8Crj2xozWm'


def validate_settings():
    if not settings.EXECUTION_ENDPOINTS:
        raise ValueError('EXECUTION_ENDPOINTS is missing')

    if not settings.CONSENSUS_ENDPOINTS:
        raise ValueError('CONSENSUS_ENDPOINTS is missing')


async def wait_for_consensus_node() -> None:
    done = False
    while True:
        for consensus_endpoint in settings.CONSENSUS_ENDPOINTS:
            try:
                consensus_client = get_consensus_client([consensus_endpoint])
                syncing = await consensus_client.get_syncing()
                if syncing['data']['is_syncing'] is True:
                    logger.warning(
                        'The consensus node located at %s has not completed synchronization yet. '
                        'The remaining synchronization distance is %s.',
                        consensus_endpoint,
                        syncing['data']['sync_distance'],
                    )
                    continue
                data = await consensus_client.get_finality_checkpoint()
                logger.info(
                    'Connected to consensus node at %s. Finalized epoch: %s',
                    consensus_endpoint,
                    data['data']['finalized']['epoch'],
                )
                done = True
            except Exception as e:
                logger.warning(
                    'Failed to connect to consensus node at %s. %s',
                    consensus_endpoint,
                    e,
                )
        if done:
            return
        logger.warning('Failed to connect to consensus nodes. Retrying in 10 seconds...')
        await asyncio.sleep(10)


async def wait_for_execution_node() -> None:
    done = False
    while True:
        for execution_endpoint in settings.EXECUTION_ENDPOINTS:
            try:
                execution_client = get_execution_client([execution_endpoint])

                syncing = await execution_client.eth.syncing
                if syncing is True:
                    logger.warning(
                        'The execution node located at %s has not completed synchronization yet.',
                        execution_endpoint,
                    )
                    continue
                block_number = await execution_client.eth.block_number  # type: ignore
                logger.info(
                    'Connected to execution node at %s. Current block number: %s',
                    execution_endpoint,
                    block_number,
                )
                done = True
            except Exception as e:
                logger.warning(
                    'Failed to connect to execution node at %s. %s',
                    execution_endpoint,
                    e,
                )
        if done:
            return
        logger.warning('Failed to connect to consensus nodes. Retrying in 10 seconds...')
        await asyncio.sleep(10)


async def collect_healthy_oracles() -> list:
    oracles = (await get_oracles()).endpoints

    async with ClientSession(timeout=ClientTimeout(60)) as session:
        results = await asyncio.gather(
            *[_aiohttp_fetch(session=session, url=endpoint) for endpoint in oracles],
            return_exceptions=True
        )

    healthy_oracles = []
    for result in results:
        if isinstance(result, BaseException):
            logger.error(result)
            continue

        if result:
            healthy_oracles.append(result)

    return healthy_oracles


def wait_for_keystores_path() -> None:
    while not path.exists(settings.KEYSTORES_PATH):
        logger.warning(
            "Can't find keystores directory (%s)",
            settings.KEYSTORES_PATH,
        )
        time.sleep(15)


def wait_for_keystores_password_file() -> None:
    while not path.exists(settings.KEYSTORES_PASSWORD_FILE):  # type: ignore
        logger.warning("Can't find password file (%s)", settings.KEYSTORES_PASSWORD_FILE)
        time.sleep(15)


def wait_for_keystores_password_dir() -> None:
    while not path.exists(settings.KEYSTORES_PASSWORD_DIR):  # type: ignore
        logger.warning("Can't find password dir (%s)", settings.KEYSTORES_PASSWORD_DIR)
        time.sleep(15)


async def wait_for_deposit_data_file() -> None:
    while not path.exists(settings.DEPOSIT_DATA_PATH):
        logger.warning("Can't find deposit data file (%s)", settings.DEPOSIT_DATA_PATH)
        time.sleep(15)
    deposit_data = load_deposit_data()

    while True:
        try:
            await check_deposit_data_root(deposit_data.tree.root)
            break
        except RuntimeError as e:
            logger.warning(e)
            time.sleep(15)
    logger.info('Found deposit data file %s', settings.DEPOSIT_DATA_PATH)


async def wait_for_keystore_files() -> None:
    keystores_count = count_files_in_folder(settings.KEYSTORES_PATH, '.json')
    while await count_deposit_data_non_exited_keys() >= keystores_count:
        logger.warning(
            '''The number of validators in deposit data
            (%s) and keystores directory (%s) is different.''',
            settings.DEPOSIT_DATA_PATH,
            settings.KEYSTORES_PATH,
        )
        time.sleep(15)


async def startup_checks():
    validate_settings()

    logger.info('Checking hot wallet balance %s...', hot_wallet.address)

    await check_hot_wallet_balance()

    logger.info('Checking connection to database...')
    db_client.create_db_dir()
    with db_client.get_db_connection() as conn:
        conn.cursor()
    logger.info('Connected to database %s.', settings.DATABASE)

    logger.info('Checking connection to consensus nodes...')
    await wait_for_consensus_node()

    logger.info('Checking connection to execution nodes...')
    await wait_for_execution_node()

    logger.info('Checking connection to ipfs nodes...')
    healthy_ipfs_endpoint = []
    for endpoint in settings.IPFS_FETCH_ENDPOINTS:
        client = IpfsFetchClient([endpoint])
        try:
            await client.fetch_json(IPFS_HASH_EXAMPLE)
        except Exception as e:
            logger.warning("Can't connect to ipfs node %s: %s", endpoint, e)
        else:
            healthy_ipfs_endpoint.append(endpoint)
    logger.info('Connected to ipfs nodes at %s.', ', '.join(healthy_ipfs_endpoint))

    logger.info('Checking connection to oracles set...')
    healthy_oracles = await collect_healthy_oracles()
    logger.info('Connected to oracles at %s', ', '.join(healthy_oracles))

    logger.info('Checking deposit data file...')
    await wait_for_deposit_data_file()

    if not settings.KEYSTORES_PASSWORD_FILE and not settings.KEYSTORES_PASSWORD_DIR:
        raise ValueError('KEYSTORES_PASSWORD_FILE or KEYSTORES_PASSWORD_DIR must be set')

    if settings.KEYSTORES_PASSWORD_FILE and settings.KEYSTORES_PASSWORD_DIR:
        raise ValueError(
            'Only one of KEYSTORES_PASSWORD_FILE or KEYSTORES_PASSWORD_DIR must be set'
        )

    logger.info('Checking keystores dir...')
    wait_for_keystores_path()
    logger.info('Found keystores dir')

    if settings.KEYSTORES_PASSWORD_FILE:
        logger.info('Checking keystore password file...')
        wait_for_keystores_password_file()
        logger.info('Found keystores password file')

    if settings.KEYSTORES_PASSWORD_DIR:
        logger.info('Checking keystore password dir...')
        wait_for_keystores_password_dir()
        logger.info('Found keystores password dir')

    logger.info('Checking keystore files...')
    await wait_for_keystore_files()
    logger.info('Found keystore files')


async def _aiohttp_fetch(session, url) -> str:
    async with session.get(url=url) as response:
        response.raise_for_status()
    return url
