import asyncio
import logging
import time
from os import path

from aiohttp import ClientSession, ClientTimeout
from sw_utils import IpfsFetchClient

from src.common.accounts import OperatorAccount
from src.common.clients import ConsensusClient, ExecutionClient, db_client
from src.common.execution import check_operator_balance, get_oracles
from src.common.utils import count_files_in_folder
from src.config.settings import SettingsStore
from src.validators.utils import count_deposit_data_non_exited_keys

logger = logging.getLogger(__name__)

IPFS_HASH_EXAMPLE = 'QmawUdo17Fvo7xa6ARCUSMV1eoVwPtVuzx8L8Crj2xozWm'


async def wait_for_consensus_node() -> None:
    while True:
        try:
            data = await ConsensusClient().client.get_finality_checkpoint()
            logger.info(
                'Connected to consensus node at %s. Finalized epoch: %s',
                SettingsStore().CONSENSUS_ENDPOINT,
                data['data']['finalized']['epoch'],
            )
            break
        except Exception as e:
            logger.warning('Failed to connect to consensus node. Retrying in 10 seconds: %s', e)
            await asyncio.sleep(10)


async def wait_for_execution_node() -> None:
    while True:
        try:
            block_number = await ExecutionClient().client.eth.block_number  # type: ignore
            logger.info(
                'Connected to execution node at %s. Current block number: %s',
                SettingsStore().EXECUTION_ENDPOINT,
                block_number,
            )
            break
        except Exception as e:
            logger.warning('Failed to connect to execution node. Retrying in 10 seconds: %s', e)
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
    while not path.exists(SettingsStore().KEYSTORES_PATH):
        logger.warning(
            "Can't find keystores directory (%s)",
            SettingsStore.KEYSTORES_PATH,
        )
        time.sleep(15)


def wait_for_keystores_password_file() -> None:
    while not path.exists(SettingsStore().KEYSTORES_PASSWORD_FILE):  # type: ignore
        logger.warning(
            "Can't find password file (%s)",
            SettingsStore().KEYSTORES_PASSWORD_FILE
        )
        time.sleep(15)


def wait_for_keystores_password_dir() -> None:
    while not path.exists(SettingsStore().KEYSTORES_PASSWORD_DIR):  # type: ignore
        logger.warning(
            "Can't find password dir (%s)",
            SettingsStore().KEYSTORES_PASSWORD_DIR
        )
        time.sleep(15)


async def wait_for_keystore_files() -> None:
    keystores_count = count_files_in_folder(SettingsStore().KEYSTORES_PATH, '.json')
    while (
        await count_deposit_data_non_exited_keys() >= keystores_count
    ):
        logger.warning(
            '''The number of validators in deposit data
            (%s) and keystores directory (%s) is different.''',
            SettingsStore().DEPOSIT_DATA_PATH,
            SettingsStore().KEYSTORES_PATH
        )
        time.sleep(15)


async def startup_checks():
    logger.info('Checking operator account %s...', OperatorAccount().operator_account.address)

    await check_operator_balance()

    logger.info('Checking connection to database...')
    db_client.create_db_dir()
    with db_client.get_db_connection() as conn:
        conn.cursor()
    logger.info('Connected to database %s.', SettingsStore().DATABASE)

    logger.info('Checking connection to consensus node...')
    await wait_for_consensus_node()

    logger.info('Checking connection to execution node...')
    await wait_for_execution_node()

    logger.info('Checking connection to ipfs nodes...')
    healthy_ipfs_endpoint = []
    for endpoint in SettingsStore().IPFS_FETCH_ENDPOINTS:
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

    logger.info('Checking deposit data file exists...')
    while not path.exists(SettingsStore().DEPOSIT_DATA_PATH):
        logger.warning("Can't find deposit data file (%s)", SettingsStore().DEPOSIT_DATA_PATH)
        time.sleep(15)
    logger.info('Found deposit data file at %s', SettingsStore().DEPOSIT_DATA_PATH)

    if not SettingsStore().KEYSTORES_PASSWORD_FILE and not SettingsStore().KEYSTORES_PASSWORD_DIR:
        raise ValueError('KEYSTORES_PASSWORD_FILE or KEYSTORES_PASSWORD_DIR must be set')

    if SettingsStore().KEYSTORES_PASSWORD_FILE and SettingsStore().KEYSTORES_PASSWORD_DIR:
        raise ValueError(
            'Only one of KEYSTORES_PASSWORD_FILE or KEYSTORES_PASSWORD_DIR must be set'
        )

    logger.info('Checking keystores dir...')
    wait_for_keystores_path()
    logger.info('Found keystores dir')

    if SettingsStore().KEYSTORES_PASSWORD_FILE:
        logger.info('Checking keystore password file...')
        wait_for_keystores_password_file()
        logger.info('Found keystores password file')

    if SettingsStore().KEYSTORES_PASSWORD_DIR:
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
