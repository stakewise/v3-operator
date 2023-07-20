import logging
import statistics

from eth_typing import HexStr
from sw_utils.decorators import retry_aiohttp_errors
from web3 import Web3
from web3.exceptions import MethodUnavailable
from web3.types import BlockData, ChecksumAddress, TxData, Wei

from src.common.clients import execution_client, ipfs_fetch_client
from src.common.contracts import keeper_contract
from src.common.metrics import metrics
from src.common.typings import Oracles, RewardVoteInfo
from src.common.wallet import hot_wallet
from src.config.settings import DEFAULT_RETRY_TIME, settings

SECONDS_PER_MONTH: int = 2628000

logger = logging.getLogger(__name__)


@retry_aiohttp_errors(delay=300)
async def get_hot_wallet_balance() -> Wei:
    return await execution_client.eth.get_balance(hot_wallet.address)  # type: ignore


@retry_aiohttp_errors(delay=300)
async def can_harvest(vault_address: ChecksumAddress) -> bool:
    return await keeper_contract.functions.canHarvest(vault_address).call()


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
        endpoints.append(oracle['endpoint'])
        public_keys.append(oracle['public_key'])

    if not 1 <= rewards_threshold <= len(config['oracles']):
        raise ValueError('Invalid rewards threshold')

    if not 1 <= validators_threshold <= len(config['oracles']):
        raise ValueError('Invalid validators threshold')

    exit_signature_recover_threshold = config['exit_signature_recover_threshold']

    if exit_signature_recover_threshold > validators_threshold:
        raise ValueError('Invalid exit signature threshold')

    if len(public_keys) != len(set(public_keys)):
        raise ValueError('Duplicate public keys in oracles config')

    validators_approval_batch_limit = config['validators_approval_batch_limit']
    validators_exit_rotation_batch_limit = config['validators_exit_rotation_batch_limit']

    return Oracles(
        rewards_threshold=rewards_threshold,
        validators_threshold=validators_threshold,
        exit_signature_recover_threshold=exit_signature_recover_threshold,
        public_keys=public_keys,
        endpoints=endpoints,
        validators_approval_batch_limit=validators_approval_batch_limit,
        validators_exit_rotation_batch_limit=validators_exit_rotation_batch_limit,
    )


async def get_last_rewards_update() -> RewardVoteInfo | None:
    """Fetches the last rewards update."""
    last_event = await keeper_contract.get_reward_updated_event()
    if not last_event:
        return None

    voting_info = RewardVoteInfo(
        ipfs_hash=last_event['args']['rewardsIpfsHash'],
        rewards_root=last_event['args']['rewardsRoot'],
    )
    return voting_info


async def get_max_fee_per_gas() -> Wei:
    try:
        priority_fee = await execution_client.eth.max_priority_fee  # type: ignore
    except MethodUnavailable:
        priority_fee = await calculate_median_priority_fee()  # type: ignore
    latest_block = await eth_get_block()  # type: ignore
    base_fee = latest_block['baseFeePerGas']
    max_fee_per_gas = priority_fee + 2 * base_fee
    return Wei(max_fee_per_gas)


async def calculate_median_priority_fee(block_id: str = 'latest') -> Wei:
    block = await eth_get_block(block_id)

    # collect maxPriorityFeePerGas for all transactions in the block
    priority_fees = []
    for tx_hash in block.transactions:
        tx = await eth_get_transaction(HexStr(tx_hash))
        if 'maxPriorityFeePerGas' in tx:
            priority_fees.append(tx.maxPriorityFeePerGas)

    if not priority_fees:
        return await calculate_median_priority_fee(block['number'] - 1)

    return Wei(statistics.median(priority_fees))


@retry_aiohttp_errors(delay=DEFAULT_RETRY_TIME)
async def eth_get_block(block_id: str = 'latest') -> BlockData:
    return await execution_client.eth.get_block(block_id)


@retry_aiohttp_errors(delay=DEFAULT_RETRY_TIME)
async def eth_get_transaction(tx_hash: HexStr) -> TxData:
    return await execution_client.eth.get_transaction(tx_hash)
