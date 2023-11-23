import logging
import statistics
from typing import cast

from eth_typing import BlockNumber
from web3 import Web3
from web3.exceptions import MethodUnavailable
from web3.types import BlockIdentifier, Wei

from src.common.clients import execution_client, ipfs_fetch_client
from src.common.contracts import keeper_contract, multicall_contract
from src.common.metrics import metrics
from src.common.typings import Oracles, OraclesCache
from src.common.wallet import hot_wallet
from src.config.settings import settings

SECONDS_PER_MONTH: int = 2628000

logger = logging.getLogger(__name__)


async def get_hot_wallet_balance() -> Wei:
    return await execution_client.eth.get_balance(hot_wallet.address)


async def check_hot_wallet_balance() -> None:
    hot_wallet_min_balance = settings.network_config.HOT_WALLET_MIN_BALANCE
    symbol = settings.network_config.SYMBOL

    if hot_wallet_min_balance <= 0:
        return

    hot_wallet_balance = await get_hot_wallet_balance()

    metrics.wallet_balance.set(hot_wallet_balance)

    if hot_wallet_balance < hot_wallet_min_balance:
        logger.warning(
            'Wallet %s balance is too low. At least %s %s is recommended.',
            hot_wallet.address,
            Web3.from_wei(hot_wallet_min_balance, 'ether'),
            symbol,
        )


_oracles_cache: OraclesCache | None = None


async def update_oracles_cache() -> None:
    """
    Fetches latest oracle config from IPFS. Uses cache if possible.
    """
    global _oracles_cache  # pylint: disable=global-statement

    # Find the latest block for which oracle config is cached
    if _oracles_cache:
        from_block = BlockNumber(_oracles_cache.checkpoint_block + 1)
    else:
        from_block = settings.network_config.KEEPER_GENESIS_BLOCK

    to_block = await execution_client.eth.get_block_number()

    if from_block > to_block:
        return

    logger.debug('update_oracles_cache: get logs from_block %s, to_block %s', from_block, to_block)
    event = await keeper_contract.get_config_updated_event(from_block=from_block, to_block=to_block)
    if event:
        ipfs_hash = event['args']['configIpfsHash']
        config = cast(dict, await ipfs_fetch_client.fetch_json(ipfs_hash))
    else:
        config = _oracles_cache.config  # type: ignore

    rewards_threshold_call = keeper_contract.encode_abi(fn_name='rewardsMinOracles', args=[])
    validators_threshold_call = keeper_contract.encode_abi(fn_name='validatorsMinOracles', args=[])
    multicall_response = await multicall_contract.aggregate(
        [
            (keeper_contract.address, False, rewards_threshold_call),
            (keeper_contract.address, False, validators_threshold_call),
        ],
        block_number=to_block,
    )
    rewards_threshold = Web3.to_int(multicall_response[0][1])
    validators_threshold = Web3.to_int(multicall_response[1][1])

    _oracles_cache = OraclesCache(
        config=config,
        validators_threshold=validators_threshold,
        rewards_threshold=rewards_threshold,
        checkpoint_block=to_block,
    )


async def get_oracles() -> Oracles:
    await update_oracles_cache()

    oracles_cache = cast(OraclesCache, _oracles_cache)

    config = oracles_cache.config
    rewards_threshold = oracles_cache.rewards_threshold
    validators_threshold = oracles_cache.validators_threshold

    endpoints = []
    public_keys = []
    for oracle in config['oracles']:
        endpoints.append(oracle['endpoints'])
        public_keys.append(oracle['public_key'])

    if not 1 <= rewards_threshold <= len(config['oracles']):
        raise ValueError('Invalid rewards threshold')

    if not 1 <= validators_threshold <= len(config['oracles']):
        raise ValueError('Invalid validators threshold')

    exit_signature_recover_threshold = config['exit_signature_recover_threshold']

    if exit_signature_recover_threshold > validators_threshold:
        raise ValueError('Invalid exit signature threshold')

    signature_validity_period = config['signature_validity_period']

    if signature_validity_period < 0:
        raise ValueError('Invalid signature validity period')

    if len(public_keys) != len(set(public_keys)):
        raise ValueError('Duplicate public keys in oracles config')

    validators_approval_batch_limit = config['validators_approval_batch_limit']
    validators_exit_rotation_batch_limit = config['validators_exit_rotation_batch_limit']

    return Oracles(
        rewards_threshold=rewards_threshold,
        validators_threshold=validators_threshold,
        exit_signature_recover_threshold=exit_signature_recover_threshold,
        signature_validity_period=signature_validity_period,
        public_keys=public_keys,
        endpoints=endpoints,
        validators_approval_batch_limit=validators_approval_batch_limit,
        validators_exit_rotation_batch_limit=validators_exit_rotation_batch_limit,
    )


async def check_gas_price() -> bool:
    max_fee_per_gas = await _get_max_fee_per_gas()
    if max_fee_per_gas >= Web3.to_wei(settings.max_fee_per_gas_gwei, 'gwei'):
        logging.warning(
            'Current gas price (%s gwei) is too high. '
            'Will try to submit transaction on the next block if the gas '
            'price is acceptable.',
            Web3.from_wei(max_fee_per_gas, 'gwei'),
        )
        return False

    return True


async def _get_max_fee_per_gas() -> Wei:
    try:
        priority_fee = await execution_client.eth.max_priority_fee
    except MethodUnavailable:
        priority_fee = await _calculate_median_priority_fee()
    latest_block = await execution_client.eth.get_block('latest')
    base_fee = latest_block['baseFeePerGas']
    max_fee_per_gas = priority_fee + 2 * base_fee
    return Wei(max_fee_per_gas)


async def _calculate_median_priority_fee(block_id: BlockIdentifier = 'latest') -> Wei:
    block = await execution_client.eth.get_block(block_id)

    # collect maxPriorityFeePerGas for all transactions in the block
    priority_fees = []
    for tx_hash in block.transactions:  # type: ignore[attr-defined]
        tx = await execution_client.eth.get_transaction(tx_hash)
        if 'maxPriorityFeePerGas' in tx:
            priority_fees.append(tx.maxPriorityFeePerGas)  # type: ignore[attr-defined]

    if not priority_fees:
        return await _calculate_median_priority_fee(block['number'] - 1)

    return Wei(statistics.median(priority_fees))
