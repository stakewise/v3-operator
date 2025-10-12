from unittest.mock import AsyncMock

import pytest
from sw_utils import HOODI, ValidatorStatus
from web3 import Web3

from src.common.tests.factories import create_chain_head
from src.common.typings import PendingPartialWithdrawal
from src.config.settings import settings
from src.validators.tests.factories import create_consensus_validator
from src.withdrawals import assets
from src.withdrawals.assets import (
    _calculate_validators_exits_amount,
    _get_pending_partial_withdrawals_amount,
)


@pytest.mark.asyncio
async def test_get_pending_partial_withdrawals(data_dir):
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)
    assets.get_pending_partial_withdrawals = AsyncMock(return_value=[])
    validators = [
        create_consensus_validator(index=1, balance=32),
        create_consensus_validator(index=2, balance=48),
    ]
    chain_head = create_chain_head(block_number=12345)
    result = await _get_pending_partial_withdrawals_amount(validators, chain_head)
    assert result == Web3.to_wei(0, 'gwei')

    # sums amounts for matching validator indexes
    assets.get_pending_partial_withdrawals = AsyncMock(
        return_value=[
            PendingPartialWithdrawal(validator_index=1, amount=10),
            PendingPartialWithdrawal(validator_index=2, amount=20),
        ]
    )
    result = await _get_pending_partial_withdrawals_amount(validators, chain_head)
    assert result == Web3.to_wei(30, 'gwei')

    # handles empty validator indexes list
    assets.get_pending_partial_withdrawals = AsyncMock(
        return_value=[
            PendingPartialWithdrawal(validator_index=1, amount=10),
            PendingPartialWithdrawal(validator_index=2, amount=20),
        ]
    )
    result = await _get_pending_partial_withdrawals_amount([], chain_head)
    assert result == Web3.to_wei(0, 'gwei')

    # handles large amounts correctly
    assets.get_pending_partial_withdrawals = AsyncMock(
        return_value=[
            PendingPartialWithdrawal(validator_index=1, amount=2**60),
            PendingPartialWithdrawal(validator_index=2, amount=2**60),
        ]
    )
    result = await _get_pending_partial_withdrawals_amount(validators, chain_head)
    assert result == Web3.to_wei(2**61, 'gwei')


def test_calculate_validators_exits_amount():
    # calculates_correct_balance_for_oracle_exiting_validators
    oracle_exiting_validators = [
        create_consensus_validator(index=1, balance=32),
        create_consensus_validator(index=2, balance=16),
    ]
    consensus_validators = []
    source_consolidations_indexes = set()
    result = _calculate_validators_exits_amount(
        consensus_validators, oracle_exiting_validators, source_consolidations_indexes
    )
    assert result == Web3.to_wei(48, 'gwei')

    # excludes_validators_in_source_consolidations_indexes
    oracle_exiting_validators = []
    consensus_validators = [
        create_consensus_validator(index=1, balance=32, status=ValidatorStatus.ACTIVE_EXITING),
        create_consensus_validator(index=2, balance=16, status=ValidatorStatus.ACTIVE_EXITING),
    ]
    source_consolidations_indexes = {1}
    result = _calculate_validators_exits_amount(
        consensus_validators, oracle_exiting_validators, source_consolidations_indexes
    )
    assert result == Web3.to_wei(16, 'gwei')

    # excludes_validators_not_in_exiting_status
    oracle_exiting_validators = []
    consensus_validators = [
        create_consensus_validator(index=1, balance=32, status=ValidatorStatus.ACTIVE_ONGOING),
        create_consensus_validator(index=2, balance=16, status=ValidatorStatus.EXITED_UNSLASHED),
    ]
    source_consolidations_indexes = set()
    result = _calculate_validators_exits_amount(
        consensus_validators, oracle_exiting_validators, source_consolidations_indexes
    )
    assert result == Web3.to_wei(16, 'gwei')

    # calculates_combined_balance_for_oracle_and_manual_exits
    oracle_exiting_validators = [
        create_consensus_validator(index=1, balance=32),
    ]
    consensus_validators = [
        create_consensus_validator(index=2, balance=16, status=ValidatorStatus.ACTIVE_EXITING),
    ]
    source_consolidations_indexes = set()
    result = _calculate_validators_exits_amount(
        consensus_validators, oracle_exiting_validators, source_consolidations_indexes
    )
    assert result == Web3.to_wei(48, 'gwei')

    # returns_zero_when_no_validators_provided
    oracle_exiting_validators = []
    consensus_validators = []
    source_consolidations_indexes = set()
    result = _calculate_validators_exits_amount(
        consensus_validators, oracle_exiting_validators, source_consolidations_indexes
    )
    assert result == Web3.to_wei(0, 'gwei')
