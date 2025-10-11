import asyncio
import logging
from typing import cast

from eth_typing import BlockNumber
from hexbytes import HexBytes
from sw_utils import (
    ChainHead,
    GasManager,
    InterruptHandler,
    ProtocolConfig,
    build_protocol_config,
)
from web3 import Web3
from web3.contract.async_contract import AsyncContractFunction
from web3.types import Gwei, TxParams, Wei

from src.common.app_state import AppState, OraclesCache
from src.common.clients import consensus_client, execution_client, ipfs_fetch_client
from src.common.contracts import keeper_contract, multicall_contract
from src.common.metrics import metrics
from src.common.tasks import BaseTask
from src.common.typings import PendingConsolidation, PendingPartialWithdrawal
from src.common.wallet import wallet
from src.config.settings import ATTEMPTS_WITH_DEFAULT_GAS, settings
from src.validators.typings import ConsensusValidator

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
        await check_wallet_balance()


async def check_wallet_balance() -> None:
    wallet_min_balance = settings.network_config.WALLET_MIN_BALANCE
    symbol = settings.network_config.WALLET_BALANCE_SYMBOL

    if wallet_min_balance <= 0:
        return

    wallet_balance = await get_wallet_balance()

    metrics.wallet_balance.labels(network=settings.network).set(wallet_balance)

    if wallet_balance < wallet_min_balance:
        logger.warning(
            'Wallet %s balance is too low. At least %s %s is recommended.',
            wallet.address,
            Web3.from_wei(wallet_min_balance, 'ether'),
            symbol,
        )


async def get_wallet_balance() -> Wei:
    return await execution_client.eth.get_balance(wallet.address)


async def transaction_gas_wrapper(
    tx_function: AsyncContractFunction, tx_params: TxParams | None = None
) -> HexBytes:
    """Handles periods with high gas in the network."""
    if not tx_params:
        tx_params = {}

    # trying to submit with basic gas
    for i in range(ATTEMPTS_WITH_DEFAULT_GAS):
        try:
            return await tx_function.transact(tx_params)
        except ValueError as e:
            # Handle only FeeTooLow error
            code = None
            if e.args and isinstance(e.args[0], dict):
                code = e.args[0].get('code')
            if not code or code != -32010:
                raise e
            if i < ATTEMPTS_WITH_DEFAULT_GAS - 1:  # skip last sleep
                await asyncio.sleep(settings.network_config.SECONDS_PER_BLOCK)

    # use high priority fee
    gas_manager = build_gas_manager()
    tx_params = tx_params | await gas_manager.get_high_priority_tx_params()
    return await tx_function.transact(tx_params)


def build_gas_manager() -> GasManager:
    min_effective_priority_fee_per_gas = settings.network_config.MIN_EFFECTIVE_PRIORITY_FEE_PER_GAS
    return GasManager(
        execution_client=execution_client,
        max_fee_per_gas=Web3.to_wei(settings.max_fee_per_gas_gwei, 'gwei'),
        priority_fee_num_blocks=settings.priority_fee_num_blocks,
        priority_fee_percentile=settings.priority_fee_percentile,
        min_effective_priority_fee_per_gas=min_effective_priority_fee_per_gas,
    )


async def get_pending_consolidations(
    chain_head: ChainHead, consensus_validators: list[ConsensusValidator]
) -> list[PendingConsolidation]:
    consensus_consolidations = await consensus_client.get_pending_consolidations(
        str(chain_head.slot)
    )
    indexes = set()
    public_key_to_index = {}
    for val in consensus_validators:
        indexes.add(val.index)
        public_key_to_index[val.public_key] = val.index

    result = []
    for cons in consensus_consolidations:
        source_idx = cons['source_index']
        target_idx = cons['target_index']

        has_source = source_idx in indexes
        has_target = target_idx in indexes
        if not has_source and not has_target:
            continue

        if has_source and not has_target:
            raise ValueError(f'Target validator index {target_idx} not found in vault validators')

        result.append(PendingConsolidation(source_index=source_idx, target_index=target_idx))

    execution_consolidations = await get_execution_consolidations(chain_head.block_number)
    for cons in execution_consolidations:
        source_pubkey = cons['source_pubkey']
        target_pubkey = cons['target_pubkey']

        source_idx = public_key_to_index.get(source_pubkey, None)
        target_idx = public_key_to_index.get(target_pubkey, None)
        if source_idx is None and target_idx is None:
            continue

        if source_idx is not None and target_idx is None:
            raise ValueError(
                f'Target validator pubkey {target_pubkey} not found in vault validators'
            )

        result.append(PendingConsolidation(source_index=source_idx, target_index=target_idx))

    return result


async def get_execution_consolidations(block_number: BlockNumber | None = None) -> list[dict]:
    queue_head_index_bytes = await execution_client.eth.get_storage_at(
        settings.network_config.CONSOLIDATION_CONTRACT_ADDRESS,
        settings.network_config.EXECUTION_REQUEST_QUEUE_HEAD_STORAGE_SLOT,
        block_identifier=block_number,
    )
    queue_head_index = Web3.to_int(queue_head_index_bytes)

    queue_tail_index_bytes = await execution_client.eth.get_storage_at(
        settings.network_config.CONSOLIDATION_CONTRACT_ADDRESS,
        settings.network_config.EXECUTION_REQUEST_QUEUE_TAIL_STORAGE_SLOT,
        block_identifier=block_number,
    )
    queue_tail_index = Web3.to_int(queue_tail_index_bytes)
    queue_length = queue_tail_index - queue_head_index

    execution_consolidations = []
    for i in range(queue_length):
        queue_storage_slot = (
            settings.network_config.EXECUTION_REQUEST_QUEUE_STORAGE_OFFSET
            + (queue_head_index + i) * 4
        )
        storage_slot0 = await execution_client.eth.get_storage_at(
            settings.network_config.CONSOLIDATION_CONTRACT_ADDRESS,
            queue_storage_slot,
            block_identifier=block_number,
        )
        storage_slot1 = await execution_client.eth.get_storage_at(
            settings.network_config.CONSOLIDATION_CONTRACT_ADDRESS,
            queue_storage_slot + 1,
            block_identifier=block_number,
        )
        storage_slot2 = await execution_client.eth.get_storage_at(
            settings.network_config.CONSOLIDATION_CONTRACT_ADDRESS,
            queue_storage_slot + 2,
            block_identifier=block_number,
        )
        storage_slot3 = await execution_client.eth.get_storage_at(
            settings.network_config.CONSOLIDATION_CONTRACT_ADDRESS,
            queue_storage_slot + 3,
            block_identifier=block_number,
        )
        execution_consolidations.append(
            {
                'source_address': Web3.to_checksum_address(storage_slot0[0:20]),
                'source_pubkey': Web3.to_hex(storage_slot1[0:32] + storage_slot2[0:16]),
                'target_pubkey': Web3.to_hex(storage_slot2[16:32] + storage_slot3[0:32]),
            }
        )

    return execution_consolidations


async def get_consolidation_request_fee(count: int = 1, gap_count: int = 5) -> Wei:
    """
    Calculates the current consolidation request fee.
    For more details see: https://eips.ethereum.org/EIPS/eip-7251
    """
    previous_excess_bytes = await execution_client.eth.get_storage_at(
        settings.network_config.CONSOLIDATION_CONTRACT_ADDRESS,
        settings.network_config.EXCESS_EXECUTION_REQUESTS_STORAGE_SLOT,
    )
    previous_excess = Web3.to_int(previous_excess_bytes)

    count += await get_execution_consolidations_count()
    count += gap_count

    excess = 0
    target_consolidation_requests_per_block = (
        settings.network_config.TARGET_CONSOLIDATION_REQUESTS_PER_BLOCK
    )
    if previous_excess + count > target_consolidation_requests_per_block:
        excess = previous_excess + count - target_consolidation_requests_per_block

    per_validator_fee = _fake_exponential(
        settings.network_config.MIN_EXECUTION_REQUEST_FEE,
        excess,
        settings.network_config.EXECUTION_REQUEST_FEE_UPDATE_FRACTION,
    )
    return Wei(per_validator_fee)


async def get_consolidations_count() -> int:
    count = await get_execution_consolidations_count()
    consensus_consolidations = await consensus_client.get_pending_consolidations()
    return len(consensus_consolidations) + Web3.to_int(count)


async def get_execution_consolidations_count() -> int:
    count_bytes = await execution_client.eth.get_storage_at(
        settings.network_config.CONSOLIDATION_CONTRACT_ADDRESS,
        settings.network_config.EXECUTION_REQUEST_COUNT_STORAGE_SLOT,
    )
    return Web3.to_int(count_bytes)


async def get_pending_partial_withdrawals(
    chain_head: ChainHead, consensus_validators: list[ConsensusValidator]
) -> list[PendingPartialWithdrawal]:
    pending_withdrawals = await consensus_client.get_pending_partial_withdrawals(
        str(chain_head.slot)
    )
    indexes = set()
    public_key_to_index = {}
    for val in consensus_validators:
        indexes.add(val.index)
        public_key_to_index[val.public_key] = val.index

    result = []
    for withdrawal in pending_withdrawals:
        validator_index = int(withdrawal['validator_index'])
        if validator_index not in indexes:
            continue

        result.append(
            PendingPartialWithdrawal(
                validator_index=validator_index, amount=Gwei(int(withdrawal['amount']))
            )
        )

    execution_withdrawals = await get_execution_partial_withdrawals(chain_head.block_number)
    for withdrawal in execution_withdrawals:
        public_key = withdrawal['public_key']
        if public_key not in public_key_to_index:
            continue

        result.append(
            PendingPartialWithdrawal(
                validator_index=public_key_to_index[public_key], amount=Gwei(withdrawal['amount'])
            )
        )

    return result


async def get_execution_partial_withdrawals(block_number: BlockNumber | None = None) -> list[dict]:
    queue_head_index_bytes = await execution_client.eth.get_storage_at(
        settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS,
        settings.network_config.EXECUTION_REQUEST_QUEUE_HEAD_STORAGE_SLOT,
        block_identifier=block_number,
    )
    queue_head_index = Web3.to_int(queue_head_index_bytes)

    queue_tail_index_bytes = await execution_client.eth.get_storage_at(
        settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS,
        settings.network_config.EXECUTION_REQUEST_QUEUE_TAIL_STORAGE_SLOT,
        block_identifier=block_number,
    )
    queue_tail_index = Web3.to_int(queue_tail_index_bytes)
    queue_length = queue_tail_index - queue_head_index

    execution_withdrawals = []
    for i in range(queue_length):
        queue_storage_slot = (
            settings.network_config.EXECUTION_REQUEST_QUEUE_STORAGE_OFFSET
            + (queue_head_index + i) * 3
        )
        storage_slot0 = await execution_client.eth.get_storage_at(
            settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS,
            queue_storage_slot,
            block_identifier=block_number,
        )
        storage_slot1 = await execution_client.eth.get_storage_at(
            settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS,
            queue_storage_slot + 1,
            block_identifier=block_number,
        )
        storage_slot2 = await execution_client.eth.get_storage_at(
            settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS,
            queue_storage_slot + 2,
            block_identifier=block_number,
        )
        execution_withdrawals.append(
            {
                'source_address': Web3.to_checksum_address(storage_slot0[0:20]),
                'public_key': Web3.to_hex(storage_slot1[0:32] + storage_slot2[0:16]),
                'amount': int.from_bytes(storage_slot2[16:24], byteorder='little'),
            }
        )

    return execution_withdrawals


async def get_withdrawal_request_fee(count: int = 1, gap_count: int = 10) -> Wei:
    """
    Calculates the current withdrawal request fee.
    For more details see: https://eips.ethereum.org/EIPS/eip-7002
    """
    previous_excess_bytes = await execution_client.eth.get_storage_at(
        settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS,
        settings.network_config.EXCESS_EXECUTION_REQUESTS_STORAGE_SLOT,
    )
    previous_excess = Web3.to_int(previous_excess_bytes)

    count += await get_execution_withdrawals_count()
    count += gap_count

    excess = 0
    target_withdrawal_requests_per_block = (
        settings.network_config.TARGET_WITHDRAWAL_REQUESTS_PER_BLOCK
    )
    if previous_excess + count > target_withdrawal_requests_per_block:
        excess = previous_excess + count - target_withdrawal_requests_per_block

    per_validator_fee = _fake_exponential(
        settings.network_config.MIN_EXECUTION_REQUEST_FEE,
        excess,
        settings.network_config.EXECUTION_REQUEST_FEE_UPDATE_FRACTION,
    )
    return Wei(per_validator_fee)


async def get_withdrawals_count() -> int:
    count = await get_execution_withdrawals_count()
    pending_partial_withdrawals = await consensus_client.get_pending_partial_withdrawals()
    return len(pending_partial_withdrawals) + Web3.to_int(count)


async def get_execution_withdrawals_count() -> int:
    count_bytes = await execution_client.eth.get_storage_at(
        settings.network_config.WITHDRAWAL_CONTRACT_ADDRESS,
        settings.network_config.EXECUTION_REQUEST_COUNT_STORAGE_SLOT,
    )
    return Web3.to_int(count_bytes)


def _fake_exponential(factor: int, numerator: int, denominator: int) -> int:
    i = 1
    output = 0
    numerator_accum = factor * denominator
    while numerator_accum > 0:
        output += numerator_accum
        numerator_accum = (numerator_accum * numerator) // (denominator * i)
        i += 1
    return output // denominator
