import asyncio
import logging

from aiohttp import ClientSession, ClientTimeout
from sw_utils import IpfsFetchClient

from src.common.accounts import operator_account
from src.common.clients import consensus_client, db_client, execution_client
from src.config.settings import (
    CONSENSUS_ENDPOINT,
    DATABASE,
    EXECUTION_ENDPOINT,
    IPFS_FETCH_ENDPOINTS,
)
from src.validators.execution import check_operator_balance, get_oracles

logger = logging.getLogger(__name__)

IPFS_HASH_EXAMPLE = 'QmawUdo17Fvo7xa6ARCUSMV1eoVwPtVuzx8L8Crj2xozWm'


async def startup_checks():
    logger.info('Checking operator account %s...', operator_account.address)

    await check_operator_balance()

    logger.info('Checking connection to database...')
    db_client.create_db_dir()
    with db_client.get_db_connection() as conn:
        conn.cursor()
    logger.info('Connected to database %s.', DATABASE)

    logger.info('Checking connection to consensus node...')
    data = await consensus_client.get_finality_checkpoint()
    logger.info(
        'Connected to consensus node at %s. Finalized epoch: %s',
        CONSENSUS_ENDPOINT,
        data['data']['finalized']['epoch'],
    )

    logger.info('Checking connection to execution node...')
    block_number = await execution_client.eth.block_number
    logger.info(
        'Connected to execution node at %s. Current block number: %s',
        EXECUTION_ENDPOINT,
        block_number,
    )

    logger.info('Checking connection to ipfs nodes...')
    healthy_ipfs_endpoint = []
    for endpoint in IPFS_FETCH_ENDPOINTS:
        client = IpfsFetchClient([endpoint])
        try:
            await client.fetch_json(IPFS_HASH_EXAMPLE)
        except Exception as e:
            logger.warning("Can't connect to ipfs node %s: %s", endpoint, e)
        else:
            healthy_ipfs_endpoint.append(endpoint)
    logger.info('Connected to ipfs nodes at %s.', ', '.join(healthy_ipfs_endpoint))

    logger.info('Checking connection to oracles set...')
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

    logger.info('Connected to oracles at %s', ', '.join(healthy_oracles))


async def _aiohttp_fetch(session, url) -> str:
    async with session.get(url=url) as response:
        response.raise_for_status()
    return url
