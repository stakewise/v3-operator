import logging
from typing import cast

import click
from eth_typing import BlockNumber
from sw_utils import GasManager, InterruptHandler, ProtocolConfig, build_protocol_config
from web3 import Web3
from web3.exceptions import BadFunctionCallOutput
from web3.types import Wei

from src.common.app_state import AppState, OraclesCache
from src.common.clients import execution_client, ipfs_fetch_client
from src.common.contracts import keeper_contract, multicall_contract
from src.common.metrics import metrics
from src.common.tasks import BaseTask
from src.common.vault import Vault
from src.common.wallet import hot_wallet
from src.config.settings import settings

logger = logging.getLogger(__name__)


def build_gas_manager() -> GasManager:
    min_effective_priority_fee_per_gas = settings.network_config.MIN_EFFECTIVE_PRIORITY_FEE_PER_GAS
    return GasManager(
        execution_client=execution_client,
        max_fee_per_gas=Web3.to_wei(settings.max_fee_per_gas_gwei, 'gwei'),
        priority_fee_num_blocks=settings.priority_fee_num_blocks,
        priority_fee_percentile=settings.priority_fee_percentile,
        min_effective_priority_fee_per_gas=min_effective_priority_fee_per_gas,
    )


async def check_vault_address() -> None:
    try:
        await Vault().get_validators_root()
    except BadFunctionCallOutput as e:
        raise click.ClickException('Invalid vault contract address') from e


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
        # Warm cache: scan only the blocks after the cached checkpoint
        from_block = BlockNumber(oracles_cache.checkpoint_block + 1)
        if from_block > to_block:
            return

        logger.debug(
            'update_oracles_cache: get logs from block %s to block %s', from_block, to_block
        )
        event = await keeper_contract.get_config_updated_event(
            from_block=from_block, to_block=to_block
        )
        if event:
            config = await _fetch_config_by_hash(event['args']['configIpfsHash'])
        else:
            config = oracles_cache.config
    else:
        ipfs_hash = await _get_config_ipfs_hash_since_checkpoint(to_block)
        config = await _fetch_config_by_hash(ipfs_hash)

    rewards_threshold_call = keeper_contract.encode_abi(fn_name='rewardsMinOracles', args=[])
    validators_threshold_call = keeper_contract.encode_abi(fn_name='validatorsMinOracles', args=[])
    _, multicall_response = await multicall_contract.aggregate(
        [
            (keeper_contract.address, rewards_threshold_call),
            (keeper_contract.address, validators_threshold_call),
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


async def _get_config_ipfs_hash_since_checkpoint(to_block: BlockNumber) -> str:
    """
    Cold cache lookup. Scans from the checkpoint to avoid re-scanning the whole
    history, and falls back to the IPFS hash of the last known event when nothing is newer.
    The fallback doesn't read old event logs, so it works on nodes with pruned history.
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
            return event['args']['configIpfsHash']

    if not network_config.CONFIG_UPDATE_LAST_EVENT_IPFS_HASH:
        raise RuntimeError(
            "Can't find oracle config. Please, ensure that EL client didn't prune event logs."
        )
    return network_config.CONFIG_UPDATE_LAST_EVENT_IPFS_HASH


async def _fetch_config_by_hash(ipfs_hash: str) -> dict:
    return cast(dict, await ipfs_fetch_client.fetch_json(ipfs_hash))


class WalletTask(BaseTask):
    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        await check_hot_wallet_balance()


async def check_hot_wallet_balance() -> None:
    hot_wallet_min_balance = settings.network_config.HOT_WALLET_MIN_BALANCE
    symbol = settings.network_config.WALLET_BALANCE_SYMBOL

    if hot_wallet_min_balance <= 0:
        return

    hot_wallet_balance = await get_hot_wallet_balance()

    metrics.wallet_balance.labels(network=settings.network).set(hot_wallet_balance)

    if hot_wallet_balance < hot_wallet_min_balance:
        logger.warning(
            'Wallet %s balance is too low. At least %s %s is recommended.',
            hot_wallet.address,
            Web3.from_wei(hot_wallet_min_balance, 'ether'),
            symbol,
        )


async def get_hot_wallet_balance() -> Wei:
    return await execution_client.eth.get_balance(hot_wallet.address)
