import logging

from eth_typing import BlockNumber
from sw_utils import IpfsFetchClient
from web3 import Web3

from src.config.settings import settings
from src.validators.database import NetworkValidatorCrud
from src.validators.typings import NetworkValidator

logger = logging.getLogger(__name__)


async def load_genesis_validators() -> None:
    """
    Load consensus network validators from the ipfs dump.
    Used to speed up service startup
    """
    checkpoints = settings.network_config.CHECKPOINTS
    ipfs_hash = checkpoints.GENESIS_VALIDATORS_IPFS_HASH
    if not (NetworkValidatorCrud().get_last_network_validator() is None and ipfs_hash):
        return

    logger.info('Downloading validators data from IPFS...')
    data = await fetch_ipfs_dump(ipfs_hash)
    genesis_validators: list[NetworkValidator] = []
    logger.info('Loading genesis validators into the database...')
    for i in range(0, len(data), 52):
        genesis_validators.append(
            NetworkValidator(
                public_key=Web3.to_hex(data[i + 4 : i + 52]),
                block_number=BlockNumber(int.from_bytes(data[i : i + 4], 'big')),
            )
        )

    NetworkValidatorCrud().save_network_validators(genesis_validators)
    logger.info('Loaded %d genesis validators', len(genesis_validators))


async def fetch_ipfs_dump(ipfs_hash: str) -> bytes:
    ipfs_fetch_client = IpfsFetchClient(
        ipfs_endpoints=settings.ipfs_fetch_endpoints,
        timeout=settings.genesis_validators_ipfs_timeout,
        retry_timeout=settings.genesis_validators_ipfs_retry_timeout,
    )
    return await ipfs_fetch_client.fetch_bytes(ipfs_hash)
