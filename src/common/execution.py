import logging

from sw_utils.decorators import backoff_aiohttp_errors
from web3 import Web3
from web3.types import ChecksumAddress, EventData, Wei

from src.common.accounts import OperatorAccount
from src.common.clients import IpfsFetchRetryClient, execution_client
from src.common.contracts import keeper_contract, oracles_contract
from src.common.typings import Oracles, RewardVoteInfo
from src.config.settings import DEFAULT_RETRY_TIME, settings

SECONDS_PER_MONTH: int = 2628000

logger = logging.getLogger(__name__)


@backoff_aiohttp_errors(max_time=300)
async def get_operator_balance() -> Wei:
    operator_account = OperatorAccount().operator_account
    return await execution_client.eth.get_balance(operator_account.address)  # type: ignore


@backoff_aiohttp_errors(max_time=300)
async def can_harvest(vault_address: ChecksumAddress) -> bool:
    return await keeper_contract.functions.canHarvest(vault_address).call()


async def check_operator_balance() -> None:
    operator_min_balance = settings.NETWORK_CONFIG.OPERATOR_MIN_BALANCE
    symbol = settings.NETWORK_CONFIG.SYMBOL

    if operator_min_balance <= 0:
        return

    if (await get_operator_balance()) < operator_min_balance:
        logger.warning(
            'Operator balance is too low. At least %s %s is recommended.',
            Web3.from_wei(operator_min_balance, 'ether'),
            symbol,
        )


@backoff_aiohttp_errors(max_time=DEFAULT_RETRY_TIME)
async def get_oracles() -> Oracles:
    """Fetches oracles config."""
    events = await oracles_contract.events.ConfigUpdated.get_logs(
        from_block=settings.NETWORK_CONFIG.ORACLES_GENESIS_BLOCK
    )
    if not events:
        raise ValueError('Failed to fetch IPFS hash of oracles config')

    # fetch IPFS record
    ipfs_hash = events[-1]['args']['configIpfsHash']
    config: dict = await IpfsFetchRetryClient().fetch_json(ipfs_hash)  # type: ignore
    threshold = await oracles_contract.functions.requiredOracles().call()

    endpoints = []
    public_keys = []

    for oracle in config['oracles']:
        endpoints.append(oracle['endpoint'])
        public_keys.append(oracle['public_key'])

    if not 1 <= threshold <= len(config['oracles']):
        raise ValueError('Invalid threshold in oracles config')

    if len(public_keys) != len(set(public_keys)):
        raise ValueError('Duplicate public keys in oracles config')

    return Oracles(
        threshold=threshold,
        public_keys=public_keys,
        endpoints=endpoints,
    )


@backoff_aiohttp_errors(max_time=DEFAULT_RETRY_TIME)
async def get_last_rewards_update() -> RewardVoteInfo | None:
    """Fetches the last rewards update."""
    approx_blocks_per_month: int = int(
        SECONDS_PER_MONTH // settings.NETWORK_CONFIG.SECONDS_PER_BLOCK
    )
    block_number = await execution_client.eth.get_block_number()  # type: ignore
    events = await keeper_contract.events.RewardsUpdated.get_logs(
        from_block=max(
            int(settings.NETWORK_CONFIG.KEEPER_GENESIS_BLOCK),
            block_number - approx_blocks_per_month,
            0
        ),
        to_block=block_number,
    )
    if not events:
        return None

    last_event: EventData = events[-1]

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
