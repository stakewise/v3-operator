import logging
from typing import cast

import click
from eth_typing import BlockNumber
from web3 import Web3
from web3._utils.async_transactions import _max_fee_per_gas
from web3.exceptions import BadFunctionCallOutput
from web3.types import TxParams, Wei

from src.common.clients import execution_client, ipfs_fetch_client
from src.common.contracts import keeper_contract, multicall_contract, vault_contract
from src.common.metrics import metrics
from src.common.tasks import BaseTask
from src.common.typings import Oracles, OraclesCache
from src.common.wallet import hot_wallet
from src.config.settings import settings

SECONDS_PER_MONTH: int = 2628000

logger = logging.getLogger(__name__)


async def get_hot_wallet_balance() -> Wei:
    return await execution_client.eth.get_balance(hot_wallet.address)


async def check_vault_address() -> None:
    try:
        await vault_contract.get_validators_root()
    except BadFunctionCallOutput as e:
        raise click.ClickException('Invalid vault contract address') from e


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


async def get_high_priority_tx_params() -> TxParams:
    """
    `maxPriorityFeePerGas <= maxFeePerGas` must be fulfilled
    Because of that when increasing `maxPriorityFeePerGas` I have to adjust `maxFeePerGas`.
    See https://eips.ethereum.org/EIPS/eip-1559 for details.
    """
    tx_params: TxParams = {}

    max_priority_fee_per_gas = await _calc_high_priority_fee()

    # Reference: `_max_fee_per_gas` in web3/_utils/async_transactions.py
    block = await execution_client.eth.get_block('latest')
    max_fee_per_gas = Wei(max_priority_fee_per_gas + (2 * block['baseFeePerGas']))

    tx_params['maxPriorityFeePerGas'] = max_priority_fee_per_gas
    tx_params['maxFeePerGas'] = max_fee_per_gas
    logger.debug('tx_params %s', tx_params)

    return tx_params


async def _calc_high_priority_fee() -> Wei:
    """
    reference: "high" priority value from https://etherscan.io/gastracker
    """
    num_blocks = settings.priority_fee_num_blocks
    percentile = settings.priority_fee_percentile
    history = await execution_client.eth.fee_history(num_blocks, 'pending', [percentile])
    validator_rewards = [r[0] for r in history['reward']]
    mean_reward = int(sum(validator_rewards) / len(validator_rewards))

    # prettify `mean_reward`
    # same as `round(value, 1)` if value was in gwei
    mean_reward = round(mean_reward, -8)

    return Wei(mean_reward)


async def check_gas_price(high_priority: bool = False) -> bool:
    if high_priority:
        tx_params = await get_high_priority_tx_params()
        max_fee_per_gas = Wei(int(tx_params['maxFeePerGas']))
    else:
        # fallback to logic from web3
        max_fee_per_gas = await _max_fee_per_gas(execution_client, {})

    if max_fee_per_gas >= Web3.to_wei(settings.max_fee_per_gas_gwei, 'gwei'):
        logging.warning(
            'Current gas price (%s gwei) is too high. '
            'Will try to submit transaction on the next block if the gas '
            'price is acceptable.',
            Web3.from_wei(max_fee_per_gas, 'gwei'),
        )
        return False

    return True


class WalletTask(BaseTask):
    async def process_block(self) -> None:
        await check_hot_wallet_balance()
