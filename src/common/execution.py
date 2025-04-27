import logging
from typing import cast

from eth_typing import BlockNumber
from sw_utils import GasManager, InterruptHandler, ProtocolConfig, build_protocol_config
from web3 import Web3
from web3.types import Wei

from src.common.app_state import AppState, OraclesCache
from src.common.clients import execution_client, ipfs_fetch_client
from src.common.contracts import keeper_contract, multicall_contract
from src.common.metrics import metrics
from src.common.tasks import BaseTask
from src.common.wallet import hot_wallet
from src.config.settings import settings

SECONDS_PER_MONTH: int = 2628000

logger = logging.getLogger(__name__)


def build_gas_manager() -> GasManager:
    return GasManager(
        execution_client=execution_client,
        max_fee_per_gas_gwei=settings.max_fee_per_gas_gwei,
        priority_fee_num_blocks=settings.priority_fee_num_blocks,
        priority_fee_percentile=settings.priority_fee_percentile,
    )


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

    # Find the latest block for which oracle config is cached
    if oracles_cache:
        from_block = BlockNumber(oracles_cache.checkpoint_block + 1)
    else:
        from_block = settings.network_config.KEEPER_GENESIS_BLOCK

    to_block = await execution_client.eth.get_block_number()

    if from_block > to_block:
        return

    logger.debug('update_oracles_cache: get logs from block %s to block %s', from_block, to_block)
    event = await keeper_contract.get_config_updated_event(from_block=from_block, to_block=to_block)
    if event:
        ipfs_hash = event['args']['configIpfsHash']
        config = cast(dict, await ipfs_fetch_client.fetch_json(ipfs_hash))
    else:
        config = oracles_cache.config  # type: ignore

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
