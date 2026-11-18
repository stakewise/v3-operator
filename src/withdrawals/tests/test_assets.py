import contextlib
from unittest import mock

import pytest
from eth_typing import BlockNumber
from sw_utils import ValidatorStatus, convert_to_gno
from web3 import Web3
from web3.types import Gwei, Wei

from src.common.tests.factories import create_withdrawal
from src.common.typings import PendingPartialWithdrawal
from src.config.networks import GNOSIS
from src.config.settings import settings
from src.validators.tests.factories import create_consensus_validator
from src.validators.typings import ValidatorConsolidationData
from src.withdrawals.assets import (
    _calculate_validators_exits_amount,
    _sum_payload_expected_withdrawals,
    calculate_withdrawal_buffer,
    get_queued_assets,
)
from src.withdrawals.typings import ExitQueueAssets


def test_calculate_validators_exits_amount():
    # calculates_correct_balance_for_oracle_exiting_validators
    oracle_exiting_validators = [
        create_consensus_validator(index=1, balance=32),
        create_consensus_validator(index=2, balance=16),
    ]
    consensus_validators = []
    result = _calculate_validators_exits_amount(consensus_validators, oracle_exiting_validators)
    assert result == Web3.to_wei(48, 'gwei')

    # excludes_consolidation_sources
    oracle_exiting_validators = []
    consensus_validators = [
        create_consensus_validator(
            index=1,
            balance=32,
            status=ValidatorStatus.ACTIVE_EXITING,
            consolidation_data=ValidatorConsolidationData(is_source=True, is_target=False),
        ),
        create_consensus_validator(index=2, balance=16, status=ValidatorStatus.ACTIVE_EXITING),
    ]
    result = _calculate_validators_exits_amount(consensus_validators, oracle_exiting_validators)
    assert result == Web3.to_wei(16, 'gwei')

    # excludes_validators_not_in_exiting_status
    oracle_exiting_validators = []
    consensus_validators = [
        create_consensus_validator(index=1, balance=32, status=ValidatorStatus.ACTIVE_ONGOING),
        create_consensus_validator(index=2, balance=16, status=ValidatorStatus.EXITED_UNSLASHED),
    ]
    result = _calculate_validators_exits_amount(consensus_validators, oracle_exiting_validators)
    assert result == Web3.to_wei(16, 'gwei')

    # calculates_combined_balance_for_oracle_and_manual_exits
    oracle_exiting_validators = [
        create_consensus_validator(index=1, balance=32),
    ]
    consensus_validators = [
        create_consensus_validator(index=2, balance=16, status=ValidatorStatus.ACTIVE_EXITING),
    ]
    result = _calculate_validators_exits_amount(consensus_validators, oracle_exiting_validators)
    assert result == Web3.to_wei(48, 'gwei')

    # returns_zero_when_no_validators_provided
    oracle_exiting_validators = []
    consensus_validators = []
    result = _calculate_validators_exits_amount(consensus_validators, oracle_exiting_validators)
    assert result == Web3.to_wei(0, 'gwei')


@pytest.mark.usefixtures('fake_settings')
class TestGetQueuedAssets:
    async def test_missing_and_total_assets_wei_truncated_down_to_gwei(self):
        # 1 wei of dust must be truncated down, not rounded up
        missing_assets_wei = Wei(Web3.to_wei(5, 'gwei') + 1)
        total_assets_wei = Wei(Web3.to_wei(9, 'gwei') + 1)

        with _patch(
            cumulative_tickets=1,
            missing_assets=missing_assets_wei,
            total_assets=total_assets_wei,
        ) as mocks:
            result = await get_queued_assets(
                consensus_validators=[],
                oracle_exiting_validators=[],
                pending_partial_withdrawals=[],
                block_number=BlockNumber(100),
                redemption_assets=Wei(1),
                payload_expected_withdrawals=[],
            )

        assert result == ExitQueueAssets(missing=Gwei(5), total=Gwei(9))
        mocks['missing_assets'].assert_awaited_once()

    async def test_total_assets_read_from_vault(self):
        block_number = BlockNumber(100)

        with _patch(
            cumulative_tickets=10,
            missing_assets=Wei(456),
            total_assets=Web3.to_wei(20, 'gwei'),
        ) as mocks:
            result = await get_queued_assets(
                consensus_validators=[],
                oracle_exiting_validators=[],
                pending_partial_withdrawals=[],
                block_number=block_number,
                redemption_assets=Wei(123),
                payload_expected_withdrawals=[],
            )

        mocks['queued_exit_assets'].assert_awaited_once_with(
            mocks['harvest_params'].return_value, block_number
        )
        assert result.total == Gwei(20)

    async def test_second_call_skipped_when_no_missing_assets(self):
        with _patch(cumulative_tickets=0, missing_assets=Wei(0)) as mocks:
            result = await get_queued_assets(
                consensus_validators=[],
                oracle_exiting_validators=[],
                pending_partial_withdrawals=[],
                block_number=BlockNumber(100),
                redemption_assets=Wei(0),
                payload_expected_withdrawals=[],
            )

        assert result.total == Gwei(0)
        mocks['missing_assets'].assert_awaited_once()
        mocks['queued_exit_assets'].assert_not_awaited()

    async def test_withdrawing_assets_sums_all_sources(self):
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
        payload_expected_withdrawals = [create_withdrawal(validator_index=3, amount=7)]
        expected_withdrawing_assets = Web3.to_wei(10 + 20 + 32 + 16 + 7, 'gwei')

        with _patch(cumulative_tickets=0, missing_assets=Wei(0)) as mocks:
            await get_queued_assets(
                consensus_validators=consensus_validators,
                oracle_exiting_validators=oracle_exiting_validators,
                pending_partial_withdrawals=pending_partial_withdrawals,
                block_number=BlockNumber(100),
                redemption_assets=Wei(0),
                payload_expected_withdrawals=payload_expected_withdrawals,
            )

        assert _get_withdrawing_assets(mocks) == expected_withdrawing_assets

    async def test_payload_expected_withdrawals_are_converted_to_gno_with_other_assets(self):
        consensus_validators = [create_consensus_validator(index=1)]
        pending_partial_withdrawals = [PendingPartialWithdrawal(validator_index=1, amount=Gwei(32))]
        payload_expected_withdrawals = [create_withdrawal(validator_index=1, amount=64)]
        expected_withdrawing_assets = convert_to_gno(Web3.to_wei(32 + 64, 'gwei'))

        with mock.patch.object(settings, 'network', GNOSIS), _patch(
            cumulative_tickets=0, missing_assets=Wei(0)
        ) as mocks:
            await get_queued_assets(
                consensus_validators=consensus_validators,
                oracle_exiting_validators=[],
                pending_partial_withdrawals=pending_partial_withdrawals,
                block_number=BlockNumber(100),
                redemption_assets=Wei(0),
                payload_expected_withdrawals=payload_expected_withdrawals,
            )

        assert _get_withdrawing_assets(mocks) == expected_withdrawing_assets


def test_sum_payload_expected_withdrawals():
    consensus_validators = [
        create_consensus_validator(index=1),
        create_consensus_validator(index=2),
    ]
    withdrawals = [
        create_withdrawal(validator_index=1, amount=3),
        create_withdrawal(validator_index=1, amount=5),
        create_withdrawal(validator_index=99, amount=100),
        # builder indexes are never vault validator indexes
        create_withdrawal(validator_index=2**40 + 1, amount=100),
    ]

    result = _sum_payload_expected_withdrawals(consensus_validators, withdrawals)

    assert result == Web3.to_wei(3 + 5, 'gwei')


class TestCalculateWithdrawalBuffer:
    def test_120_eth_queue_uses_ratio(self):
        result = calculate_withdrawal_buffer(Gwei(120 * 10**9))
        assert result == 120_000_000

    def test_below_switch_point_uses_floor(self):
        result = calculate_withdrawal_buffer(Gwei(5_000_000))
        assert result == 10_000

    def test_zero_queue_uses_floor(self):
        result = calculate_withdrawal_buffer(Gwei(0))
        assert result == 10_000

    def test_exactly_at_switch_point(self):
        result = calculate_withdrawal_buffer(Gwei(10_000_000))
        assert result == 10_000

    def test_patched_floor_changes_result(self):
        with mock.patch('src.withdrawals.assets.MIN_WITHDRAWAL_BUFFER_GWEI', Gwei(500)):
            result = calculate_withdrawal_buffer(Gwei(5_000_000))
        assert result == 5_000

    def test_large_queue_capped(self):
        result = calculate_withdrawal_buffer(Gwei(2600 * 10**9))
        assert result == 1_000_000_000

    def test_exactly_at_cap(self):
        result = calculate_withdrawal_buffer(Gwei(1000 * 10**9))
        assert result == 1_000_000_000

    def test_floor_above_cap_is_capped(self):
        with mock.patch('src.withdrawals.assets.MIN_WITHDRAWAL_BUFFER_GWEI', Gwei(2_000_000_000)):
            result = calculate_withdrawal_buffer(Gwei(0))
        assert result == 1_000_000_000


@contextlib.contextmanager
def _patch(
    cumulative_tickets: int,
    missing_assets: Wei,
    total_assets: Wei = Wei(0),
):
    get_harvest_params_mock = mock.AsyncMock(return_value=None)
    cumulative_tickets_mock = mock.AsyncMock(return_value=cumulative_tickets)
    missing_assets_mock = mock.AsyncMock(return_value=missing_assets)
    queued_exit_assets_mock = mock.AsyncMock(return_value=total_assets)

    vault_contract_mock = mock.MagicMock()
    vault_contract_mock.return_value.get_queued_exit_assets = queued_exit_assets_mock

    with mock.patch(
        'src.withdrawals.assets.get_harvest_params', get_harvest_params_mock
    ), mock.patch.multiple(
        'src.withdrawals.assets.validators_checker_contract',
        get_exit_queue_cumulative_tickets=cumulative_tickets_mock,
        get_exit_queue_missing_assets=missing_assets_mock,
    ), mock.patch(
        'src.withdrawals.assets.VaultContract', vault_contract_mock
    ):
        yield {
            'harvest_params': get_harvest_params_mock,
            'cumulative_tickets': cumulative_tickets_mock,
            'missing_assets': missing_assets_mock,
            'queued_exit_assets': queued_exit_assets_mock,
        }


def _get_withdrawing_assets(mocks: dict[str, mock.AsyncMock]) -> Wei:
    call_kwargs = mocks['missing_assets'].call_args_list[0].kwargs
    return call_kwargs['exit_queue_missing_assets_params'].withdrawing_assets
