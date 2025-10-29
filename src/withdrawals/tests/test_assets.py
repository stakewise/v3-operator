from sw_utils import ValidatorStatus
from web3 import Web3

from src.validators.tests.factories import create_consensus_validator
from src.withdrawals.assets import _calculate_validators_exits_amount


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
