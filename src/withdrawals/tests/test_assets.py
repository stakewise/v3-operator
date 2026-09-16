import contextlib
from unittest import mock

import pytest
from sw_utils import ValidatorStatus
from web3 import Web3
from web3.types import Gwei, Wei

from src.common.tests.factories import create_chain_head
from src.common.typings import PendingPartialWithdrawal
from src.config.networks import GNOSIS, MAINNET, NETWORKS
from src.config.settings import WITHDRAWAL_BUFFER_SAFETY_FACTOR
from src.validators.tests.factories import create_consensus_validator
from src.validators.typings import ValidatorConsolidationData
from src.withdrawals.assets import (
    _calculate_validators_exits_amount,
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
    async def test_missing_and_total_assets_wei_rounded_up_to_gwei(self):
        # 1 wei of dust must round up, not truncate down
        missing_assets_wei = Wei(Web3.to_wei(5, 'gwei') + 1)
        total_assets_wei = Wei(Web3.to_wei(9, 'gwei') + 1)

        with _patch(
            cumulative_tickets=0,
            missing_assets=missing_assets_wei,
            total_assets=total_assets_wei,
        ) as mocks:
            result = await get_queued_assets(
                consensus_validators=[],
                oracle_exiting_validators=[],
                pending_partial_withdrawals=[],
                chain_head=create_chain_head(),
                redemption_assets=Wei(0),
            )

        assert result == ExitQueueAssets(missing=Gwei(6), total=Gwei(10))
        assert mocks['missing_assets'].await_count == 2

    async def test_second_call_uses_zero_withdrawing_and_redemption_assets(self):
        with _patch(cumulative_tickets=0, missing_assets=Wei(0)) as mocks:
            await get_queued_assets(
                consensus_validators=[],
                oracle_exiting_validators=[],
                pending_partial_withdrawals=[],
                chain_head=create_chain_head(),
                redemption_assets=Wei(123),
            )

        first_params = (
            mocks['missing_assets'].call_args_list[0].kwargs['exit_queue_missing_assets_params']
        )
        second_params = (
            mocks['missing_assets'].call_args_list[1].kwargs['exit_queue_missing_assets_params']
        )
        assert first_params.redemption_assets == Wei(123)
        assert second_params.withdrawing_assets == Wei(0)
        assert second_params.redemption_assets == Wei(0)

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
                pending_partial_withdrawals=pending_partial_withdrawals,
                chain_head=create_chain_head(),
                redemption_assets=Wei(0),
            )

        first_call_kwargs = mocks['missing_assets'].call_args_list[0].kwargs
        params = first_call_kwargs['exit_queue_missing_assets_params']
        assert params.withdrawing_assets == expected_withdrawing_assets


class TestCalculateWithdrawalBuffer:
    def test_120_eth_queue_zero_pending_mainnet(self):
        network_config = NETWORKS[MAINNET]
        avg_reward_per_second = 636_924_636
        rewards_delay = 43_200
        total_queue_assets = Gwei(120_000_000_000)

        result = calculate_withdrawal_buffer(
            total_queue_assets=total_queue_assets,
            pending_partials_count=0,
            avg_reward_per_second=avg_reward_per_second,
            rewards_delay=rewards_delay,
            network_config=network_config,
        )

        latency_seconds = (
            network_config.MIN_VALIDATOR_WITHDRAWABILITY_DELAY_EPOCHS
            * network_config.SECONDS_PER_EPOCH
            + rewards_delay
        )
        expected = (
            total_queue_assets
            * avg_reward_per_second
            * latency_seconds
            * WITHDRAWAL_BUFFER_SAFETY_FACTOR
            // 10**18
        )
        assert result == expected == 21_630_572

    def test_tiny_queue_yields_zero_buffer(self):
        result = calculate_withdrawal_buffer(
            total_queue_assets=Gwei(10),
            pending_partials_count=0,
            avg_reward_per_second=636_924_636,
            rewards_delay=43_200,
            network_config=NETWORKS[MAINNET],
        )
        assert result == 0

    def test_pending_partials_count_adds_sweep_wait_time(self):
        network_config = NETWORKS[MAINNET]
        kwargs = dict(
            total_queue_assets=Gwei(120_000_000_000),
            avg_reward_per_second=636_924_636,
            rewards_delay=43_200,
            network_config=network_config,
        )
        without_pending = calculate_withdrawal_buffer(pending_partials_count=0, **kwargs)
        # a full sweep's worth of pending partials adds exactly one slot of latency
        with_pending = calculate_withdrawal_buffer(
            pending_partials_count=network_config.MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP,
            **kwargs,
        )
        extra_latency_seconds = network_config.SECONDS_PER_SLOT
        expected_extra = (
            kwargs['total_queue_assets']
            * kwargs['avg_reward_per_second']
            * extra_latency_seconds
            * WITHDRAWAL_BUFFER_SAFETY_FACTOR
            // 10**18
        )
        assert with_pending - without_pending == expected_extra

    def test_gnosis_uses_its_own_slot_and_epoch_times(self):
        network_config = NETWORKS[GNOSIS]
        avg_reward_per_second = 636_924_636
        rewards_delay = 43_200
        total_queue_assets = Gwei(120_000_000_000)

        result = calculate_withdrawal_buffer(
            total_queue_assets=total_queue_assets,
            pending_partials_count=0,
            avg_reward_per_second=avg_reward_per_second,
            rewards_delay=rewards_delay,
            network_config=network_config,
        )

        latency_seconds = (
            network_config.MIN_VALIDATOR_WITHDRAWABILITY_DELAY_EPOCHS
            * network_config.SECONDS_PER_EPOCH
            + rewards_delay
        )
        expected = (
            total_queue_assets
            * avg_reward_per_second
            * latency_seconds
            * WITHDRAWAL_BUFFER_SAFETY_FACTOR
            // 10**18
        )
        assert result == expected
        assert network_config.SECONDS_PER_EPOCH != NETWORKS[MAINNET].SECONDS_PER_EPOCH


@contextlib.contextmanager
def _patch(cumulative_tickets: int, missing_assets: Wei, total_assets: Wei | None = None):
    if total_assets is None:
        total_assets = missing_assets
    get_harvest_params_mock = mock.AsyncMock(return_value=None)
    cumulative_tickets_mock = mock.AsyncMock(return_value=cumulative_tickets)
    missing_assets_mock = mock.AsyncMock(side_effect=[missing_assets, total_assets])
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
