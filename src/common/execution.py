import logging

from sw_utils.tenacity_decorators import retry_aiohttp_errors
from web3 import Web3
from web3.types import ChecksumAddress, EventData, Wei

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
    hot_wallet_min_balance = settings.NETWORK_CONFIG.HOT_WALLET_MIN_BALANCE
    symbol = settings.NETWORK_CONFIG.SYMBOL

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


@retry_aiohttp_errors(delay=DEFAULT_RETRY_TIME)
async def get_oracles() -> Oracles:
    """Fetches oracles config."""
    events = await keeper_contract.events.ConfigUpdated.get_logs(
        fromBlock=settings.NETWORK_CONFIG.KEEPER_GENESIS_BLOCK
    )
    if not events:
        raise ValueError('Failed to fetch IPFS hash of oracles config')

    # fetch IPFS record
    ipfs_hash = events[-1]['args']['configIpfsHash']
    config: dict = await ipfs_fetch_client.fetch_json(ipfs_hash)  # type: ignore
    rewards_threshold = await keeper_contract.functions.rewardsMinOracles().call()
    validators_threshold = await keeper_contract.functions.validatorsMinOracles().call()
    endpoints = []
    public_keys = []
    for oracle in config['oracles']:
        endpoints.append(oracle['endpoint'])
        public_keys.append(oracle['public_key'])

    if not 1 <= rewards_threshold <= len(config['oracles']):
        raise ValueError('Invalid rewards threshold')

    if not 1 <= validators_threshold <= len(config['oracles']):
        raise ValueError('Invalid validators threshold')

    if len(public_keys) != len(set(public_keys)):
        raise ValueError('Duplicate public keys in oracles config')

    validators_approval_batch_limit = config['validators_approval_batch_limit']
    validators_exit_rotation_batch_limit = config['validators_exit_rotation_batch_limit']

    return Oracles(
        rewards_threshold=rewards_threshold,
        validators_threshold=validators_threshold,
        public_keys=public_keys,
        endpoints=endpoints,
        validators_approval_batch_limit=validators_approval_batch_limit,
        validators_exit_rotation_batch_limit=validators_exit_rotation_batch_limit,
    )


@retry_aiohttp_errors(delay=DEFAULT_RETRY_TIME)
async def get_last_rewards_update() -> RewardVoteInfo | None:
    """Fetches the last rewards update."""
    approx_blocks_per_month: int = int(
        SECONDS_PER_MONTH // settings.NETWORK_CONFIG.SECONDS_PER_BLOCK
    )
    block_number = await execution_client.eth.get_block_number()  # type: ignore
    events = await keeper_contract.events.RewardsUpdated.get_logs(
        fromBlock=max(
            int(settings.NETWORK_CONFIG.KEEPER_GENESIS_BLOCK),
            block_number - approx_blocks_per_month,
            0,
        ),
        toBlock=block_number,
    )
    if not events:
        return None

    last_event: EventData = events[-1]

    metrics.block_number.set(block_number)

    voting_info = RewardVoteInfo(
        ipfs_hash=last_event['args']['rewardsIpfsHash'],
        rewards_root=last_event['args']['rewardsRoot'],
    )
    return voting_info


async def get_max_fee_per_gas() -> Wei:
    priority_fee = await execution_client.eth.max_priority_fee  # type: ignore
    latest_block = await execution_client.eth.get_block('latest')  # type: ignore
    base_fee = latest_block['baseFeePerGas']
    max_fee_per_gas = priority_fee + 2 * base_fee
    return Wei(max_fee_per_gas)
