import logging
from typing import cast

from eth_typing import BlockNumber
from sw_utils import ProtocolConfig, build_protocol_config
from web3 import Web3
from web3.types import EventData

from src.common.app_state import AppState, OraclesCache
from src.common.clients import execution_client, ipfs_fetch_client
from src.common.contracts import keeper_contract, multicall_contract
from src.config.settings import settings

logger = logging.getLogger(__name__)


async def get_protocol_config() -> ProtocolConfig:
    await update_oracles_cache()
    app_state = AppState()

    oracles_cache = cast(OraclesCache, app_state.oracles_cache)
    pc = build_protocol_config(
        config_data=oracles_cache.config,
        rewards_threshold=oracles_cache.rewards_threshold,
        validators_threshold=oracles_cache.validators_threshold,
    )
    return pc


async def update_oracles_cache() -> None:
    """
    Fetches latest oracle config from IPFS. Uses cache if possible.
    """
    app_state = AppState()
    oracles_cache = app_state.oracles_cache

    to_block = await execution_client.eth.get_block_number()

    if oracles_cache:
        # Warm cache: only scan blocks added since the last checkpoint.
        if oracles_cache.checkpoint_block >= to_block:
            return

        from_block = BlockNumber(oracles_cache.checkpoint_block + 1)
        logger.debug(
            'update_oracles_cache: get logs from block %s to block %s', from_block, to_block
        )
        event = await keeper_contract.get_config_updated_event(
            from_block=from_block, to_block=to_block
        )
        config = await _fetch_config(event) if event else oracles_cache.config
    else:
        # Cold cache: start from the release checkpoint instead of the keeper genesis block.
        event = await _get_config_updated_event_since_checkpoint(to_block=to_block)
        if not event:
            raise ValueError('Failed to fetch IPFS hash of oracles config')
        config = await _fetch_config(event)

    rewards_threshold_call = keeper_contract.encode_abi(fn_name='rewardsMinOracles', args=[])
    validators_threshold_call = keeper_contract.encode_abi(fn_name='validatorsMinOracles', args=[])
    _, multicall_response = await multicall_contract.aggregate(
        [
            (keeper_contract.contract_address, rewards_threshold_call),
            (keeper_contract.contract_address, validators_threshold_call),
        ],
        block_number=to_block,
    )
    rewards_threshold = Web3.to_int(multicall_response[0])
    validators_threshold = Web3.to_int(multicall_response[1])

    app_state.oracles_cache = OraclesCache(
        config=config,
        validators_threshold=validators_threshold,
        rewards_threshold=rewards_threshold,
        checkpoint_block=to_block,
    )


async def _get_config_updated_event_since_checkpoint(to_block: BlockNumber) -> EventData | None:
    """
    Cold cache lookup. Scans from the checkpoint to avoid re-scanning the whole
    history, and falls back to the last known event block when nothing is newer.
    """
    network_config = settings.network_config
    from_block = BlockNumber(network_config.CONFIG_UPDATE_CHECKPOINT_BLOCK + 1)

    if from_block <= to_block:
        logger.debug(
            'update_oracles_cache: get logs from block %s to block %s', from_block, to_block
        )
        event = await keeper_contract.get_config_updated_event(
            from_block=from_block, to_block=to_block
        )
        if event:
            return event

    last_event_block = network_config.CONFIG_UPDATE_LAST_EVENT_BLOCK
    return await keeper_contract.get_config_updated_event(
        from_block=last_event_block, to_block=last_event_block
    )


async def _fetch_config(event: EventData) -> dict:
    return cast(dict, await ipfs_fetch_client.fetch_json(event['args']['configIpfsHash']))
