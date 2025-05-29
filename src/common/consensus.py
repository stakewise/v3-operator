import logging

from eth_typing import BlockNumber, ChecksumAddress, HexStr
from eth_utils import add_0x_prefix
from sw_utils import ValidatorStatus
from sw_utils import get_chain_finalized_head as sw_get_chain_finalized_head
from sw_utils.consensus import EXITED_STATUSES
from sw_utils.typings import ChainHead

from src.common.clients import consensus_client, execution_client
from src.common.contracts import VaultContract, v2_pool_contract
from src.common.typings import ConsensusValidator
from src.config.settings import settings

EXITING_STATUSES = [ValidatorStatus.ACTIVE_EXITING] + EXITED_STATUSES
SECONDS_PER_MONTH: int = 2628000

logger = logging.getLogger(__name__)


async def get_chain_finalized_head() -> ChainHead:
    return await sw_get_chain_finalized_head(
        consensus_client=consensus_client, slots_per_epoch=settings.network_config.SLOTS_PER_EPOCH
    )


# pylint: disable-next=too-many-locals
async def fetch_v1_registered_validators(
    vault_address: ChecksumAddress,
) -> list[ConsensusValidator]:
    vault_contract = VaultContract(vault_address)
    current_block = await execution_client.eth.get_block_number()
    public_keys = await vault_contract.get_registered_validators_public_keys(
        from_block=settings.network_config.KEEPER_GENESIS_BLOCK,
        to_block=current_block,
    )
    if (
        settings.network_config.IS_SUPPORT_V2_MIGRATION
        and vault_address == settings.network_config.GENESIS_VAULT_CONTRACT_ADDRESS
    ):
        # fetch registered validators from v2 pool contract
        # new validators won't be registered after upgrade to the v3,
        # no need to check up to the latest block
        blocks_per_month = int(SECONDS_PER_MONTH // settings.network_config.SECONDS_PER_BLOCK)
        to_block = BlockNumber(
            min(
                settings.network_config.KEEPER_GENESIS_BLOCK + blocks_per_month,
                current_block,
            )
        )
        public_keys.extend(
            await v2_pool_contract.get_registered_validators_public_keys(
                from_block=settings.network_config.V2_POOL_GENESIS_BLOCK, to_block=to_block
            )
        )
    logger.info('Fetched %s registered validators', len(public_keys))

    return await _process_validators(public_keys)


async def fetch_v2_registered_validators(
    vault_address: ChecksumAddress,
) -> list[ConsensusValidator]:
    """Fetch registered validators."""
    logger.info('Fetching registered validators...')
    vault_contract = VaultContract(vault_address)
    current_block = await execution_client.eth.get_block_number()
    public_keys = await vault_contract.get_registered_v2_validators_public_keys(
        from_block=settings.network_config.KEEPER_GENESIS_BLOCK,
        to_block=current_block,
    )

    if (
        settings.network_config.IS_SUPPORT_V2_MIGRATION
        and vault_address == settings.network_config.GENESIS_VAULT_CONTRACT_ADDRESS
    ):
        # fetch registered validators from v2 pool contract
        # new validators won't be registered after upgrade to the v3,
        # no need to check up to the latest block
        blocks_per_month = int(SECONDS_PER_MONTH // settings.network_config.SECONDS_PER_BLOCK)
        to_block = BlockNumber(
            min(
                settings.network_config.KEEPER_GENESIS_BLOCK + blocks_per_month,
                current_block,
            )
        )
        public_keys.extend(
            await v2_pool_contract.get_registered_validators_public_keys(
                from_block=settings.network_config.V2_POOL_GENESIS_BLOCK, to_block=to_block
            )
        )
    logger.info('Fetched %s registered validators', len(public_keys))
    return await _process_validators(public_keys)


async def _process_validators(public_keys: list[HexStr]) -> list[ConsensusValidator]:
    logger.info('Fetching validators consensus data...')
    validators = []
    for i in range(0, len(public_keys), settings.validators_fetch_chunk_size):
        beacon_validators = await consensus_client.get_validators_by_ids(
            public_keys[i : i + settings.validators_fetch_chunk_size]
        )
        for beacon_validator in beacon_validators['data']:
            public_key = add_0x_prefix(beacon_validator['validator']['pubkey'])
            status = ValidatorStatus(beacon_validator['status'])
            if status in EXITING_STATUSES:
                continue

            validators.append(
                ConsensusValidator(
                    public_key=public_key,
                    index=int(beacon_validator['index']),
                    balance=int(beacon_validator['balance']),
                    withdrawal_credentials=beacon_validator['validator']['withdrawal_credentials'],
                    status=status,
                )
            )
    logger.info('Fetched registered validators')

    return validators
