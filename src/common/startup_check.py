import asyncio
import logging
import socket
import time
from os import path

from aiohttp import ClientSession, ClientTimeout
from sw_utils import IpfsFetchClient, get_consensus_client, get_execution_client

from src.common.clients import db_client
from src.common.execution import check_hot_wallet_balance, get_oracles
from src.common.utils import format_error, warning_verbose
from src.common.wallet import hot_wallet
from src.config.settings import settings
from src.validators.execution import check_deposit_data_root
from src.validators.utils import load_deposit_data

logger = logging.getLogger(__name__)

IPFS_HASH_EXAMPLE = 'QmawUdo17Fvo7xa6ARCUSMV1eoVwPtVuzx8L8Crj2xozWm'


def validate_settings():
    if not settings.execution_endpoints:
        raise ValueError('EXECUTION_ENDPOINTS is missing')

    if not settings.consensus_endpoints:
        raise ValueError('CONSENSUS_ENDPOINTS is missing')


async def wait_for_consensus_node() -> None:
    done = False
    while True:
        for consensus_endpoint in settings.consensus_endpoints:
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
        for execution_endpoint in settings.execution_endpoints:
            try:
                execution_client = get_execution_client([execution_endpoint])

                syncing = await execution_client.eth.syncing
                if syncing is True:
                    logger.warning(
                        'The execution node located at %s has not completed synchronization yet.',
                        execution_endpoint,
                    )
                    continue
                block_number = await execution_client.eth.block_number
                if block_number <= 0:
                    # There was a case when `block_number` equals to 0 although `syncing` is False.
                    logger.warning(
                        'Execution node %s. Current block number is %s',
                        execution_endpoint,
                        block_number,
                    )
                    continue
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
        logger.warning('Failed to connect to execution nodes. Retrying in 10 seconds...')
        await asyncio.sleep(10)


async def collect_healthy_oracles() -> list:
    endpoints = (await get_oracles()).endpoints

    async with ClientSession(timeout=ClientTimeout(60)) as session:
        results = await asyncio.gather(
            *[
                _aiohttp_fetch(session=session, url=endpoint)
                for replicas in endpoints
                for endpoint in replicas
            ],
            return_exceptions=True
        )

    healthy_oracles = []
    for result, endpoint in zip(results, endpoints):
        if isinstance(result, Exception):
            warning_verbose('%s for endpoint %s', format_error(result), endpoint)
            continue

        if result:
            healthy_oracles.append(result)

    return healthy_oracles


def check_metrics_port() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        result = sock.connect_ex((settings.metrics_host, settings.metrics_port))
        if result != 0:
            break
        logger.warning(
            "Can't start metrics server at %s:%s. Port is busy. Retrying in 10 seconds...",
            settings.metrics_host,
            settings.metrics_port,
        )
        time.sleep(10)
    sock.close()


def wait_for_keystores_dir() -> None:
    while not path.exists(settings.keystores_dir):
        logger.warning(
            "Can't find keystores directory (%s)",
            settings.keystores_dir,
        )
        time.sleep(15)


async def wait_for_deposit_data_file() -> None:
    while not path.exists(settings.deposit_data_file):
        logger.warning("Can't find deposit data file (%s)", settings.deposit_data_file)
        time.sleep(15)
    deposit_data = load_deposit_data(settings.vault, settings.deposit_data_file)

    while True:
        try:
            await check_deposit_data_root(deposit_data.tree.root)
            break
        except RuntimeError as e:
            logger.warning(e)
            time.sleep(15)
    logger.info('Found deposit data file %s', settings.deposit_data_file)


async def startup_checks():
    validate_settings()

    logger.info('Checking connection to database...')
    db_client.create_db_dir()
    with db_client.get_db_connection() as conn:
        conn.cursor()
    logger.info('Connected to database %s.', settings.database)

    logger.info('Checking connection to consensus nodes...')
    await wait_for_consensus_node()

    logger.info('Checking connection to execution nodes...')
    await wait_for_execution_node()

    logger.info('Checking hot wallet balance %s...', hot_wallet.address)
    await check_hot_wallet_balance()

    logger.info('Checking connection to ipfs nodes...')
    healthy_ipfs_endpoint = []
    for endpoint in settings.ipfs_fetch_endpoints:
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

    if settings.enable_metrics:
        logger.info('Checking metrics server...')
        check_metrics_port()

    logger.info('Checking deposit data file...')
    await wait_for_deposit_data_file()

    logger.info('Checking keystores dir...')
    wait_for_keystores_dir()
    logger.info('Found keystores dir')


async def _aiohttp_fetch(session, url) -> str:
    async with session.get(url=url) as response:
        response.raise_for_status()
    return url
