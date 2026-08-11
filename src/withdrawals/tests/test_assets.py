import contextlib
from unittest import mock

import pytest
from sw_utils import ValidatorStatus
from web3 import Web3
from web3.types import Gwei, Wei

from src.common.tests.factories import create_chain_head
from src.common.typings import PendingPartialWithdrawal
from src.validators.tests.factories import create_consensus_validator
from src.withdrawals.assets import _calculate_validators_exits_amount, get_queued_assets


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


@pytest.mark.usefixtures('fake_settings')
class TestGetQueuedAssets:
    async def test_missing_assets_wei_truncated_down_to_gwei(self):
        # 1 wei of dust must floor down, not round up
        missing_assets_wei = Wei(Web3.to_wei(5, 'gwei') + 1)

        with _patch(
            cumulative_tickets=0,
            missing_assets=missing_assets_wei,
        ) as mocks:
            result = await get_queued_assets(
                consensus_validators=[],
                oracle_exiting_validators=[],
                consolidations=[],
                pending_partial_withdrawals=[],
                chain_head=create_chain_head(),
            )

        assert result == Gwei(5)
        mocks['missing_assets'].assert_awaited_once()

    async def test_withdrawing_assets_sums_pending_partials_and_exiting_validators(self):
        pending_partial_withdrawals = [
            PendingPartialWithdrawal(validator_index=1, amount=Gwei(10)),
            PendingPartialWithdrawal(validator_index=2, amount=Gwei(20)),
        ]
        consensus_validators = [
            create_consensus_validator(
                index=3, balance=Gwei(32), status=ValidatorStatus.ACTIVE_EXITING
            ),
        ]
        oracle_exiting_validators = [
            create_consensus_validator(index=4, balance=Gwei(16)),
        ]
        expected_withdrawing_assets = Web3.to_wei(10 + 20 + 32 + 16, 'gwei')

        with _patch(cumulative_tickets=0, missing_assets=Wei(0)) as mocks:
            await get_queued_assets(
                consensus_validators=consensus_validators,
                oracle_exiting_validators=oracle_exiting_validators,
                consolidations=[],
                pending_partial_withdrawals=pending_partial_withdrawals,
                chain_head=create_chain_head(),
            )

        call_kwargs = mocks['missing_assets'].call_args.kwargs
        params = call_kwargs['exit_queue_missing_assets_params']
        assert params.withdrawing_assets == expected_withdrawing_assets


@contextlib.contextmanager
def _patch(cumulative_tickets: int, missing_assets: Wei):
    get_harvest_params_mock = mock.AsyncMock(return_value=None)
    cumulative_tickets_mock = mock.AsyncMock(return_value=cumulative_tickets)
    missing_assets_mock = mock.AsyncMock(return_value=missing_assets)
    with mock.patch(
        'src.withdrawals.assets.get_harvest_params', get_harvest_params_mock
    ), mock.patch.multiple(
        'src.withdrawals.assets.validators_checker_contract',
        get_exit_queue_cumulative_tickets=cumulative_tickets_mock,
        get_exit_queue_missing_assets=missing_assets_mock,
    ):
        yield {
            'harvest_params': get_harvest_params_mock,
            'cumulative_tickets': cumulative_tickets_mock,
            'missing_assets': missing_assets_mock,
        }
