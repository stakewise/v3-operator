import logging
import statistics

from web3 import Web3
from web3.exceptions import MethodUnavailable
from web3.types import BlockIdentifier, Wei

from src.common.clients import execution_client, ipfs_fetch_client
from src.common.contracts import keeper_contract
from src.common.metrics import metrics
from src.common.tasks import BaseTask
from src.common.typings import Oracles
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
            'Wallet balance is too low. At least %s %s is recommended.',
            Web3.from_wei(hot_wallet_min_balance, 'ether'),
            symbol,
        )


async def get_oracles() -> Oracles:
    """Fetches oracles config."""
    event = await keeper_contract.get_config_updated_event()
    if not event:
        raise ValueError('Failed to fetch IPFS hash of oracles config')

    # fetch IPFS record
    ipfs_hash = event['args']['configIpfsHash']
    config: dict = await ipfs_fetch_client.fetch_json(ipfs_hash)  # type: ignore
    rewards_threshold = await keeper_contract.get_rewards_min_oracles()
    validators_threshold = await keeper_contract.get_validators_min_oracles()
    endpoints = []
    public_keys = []
    for oracle in config['oracles']:
        if endpoint := oracle.get('endpoint'):
            replicas = [endpoint]
        else:
            replicas = oracle['endpoints']
        endpoints.append(replicas)
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


class WalletTask(BaseTask):
    async def process_block(self) -> None:
        await check_hot_wallet_balance()
