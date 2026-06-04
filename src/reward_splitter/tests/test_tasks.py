from unittest import mock

import pytest
from hexbytes import HexBytes
from sw_utils.tests import faker
from web3 import Web3
from web3.types import Wei

from src.common.contracts import RewardSplitterEncoder
from src.common.typings import ExitRequest, HarvestParams
from src.config.networks import ZERO_CHECKSUM_ADDRESS
from src.reward_splitter.tasks import (
    _get_reward_splitter_calls,
    claim_reward_splitters,
    claim_reward_splitters_for_vault,
)
from src.reward_splitter.tests.factories import create_reward_splitter


@pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
class TestGetRewardSplitterCalls:
    async def test_skips_update_state_without_harvest_params(self):
        # Meta vault flow: state already updated by the tree, so no updateVaultState call.
        reward_splitter = create_reward_splitter(
            shareholders_earned_assets=[Wei(Web3.to_wei('1', 'ether'))]
        )
        encoder = RewardSplitterEncoder()
        update_state_selector = encoder.update_vault_state(_harvest_params())[:10]

        calls = await _get_reward_splitter_calls(
            reward_splitter=reward_splitter,
            harvest_params=None,
            exit_requests=[],
        )

        shareholder = reward_splitter.shareholders[0]
        assert calls == [encoder.enter_exit_queue_on_behalf(None, shareholder.address)]
        assert all(not call.startswith(update_state_selector) for call in calls)

    async def test_includes_update_state_with_harvest_params(self):
        reward_splitter = create_reward_splitter(
            shareholders_earned_assets=[Wei(Web3.to_wei('1', 'ether'))]
        )
        encoder = RewardSplitterEncoder()
        harvest_params = _harvest_params()

        calls = await _get_reward_splitter_calls(
            reward_splitter=reward_splitter,
            harvest_params=harvest_params,
            exit_requests=[],
        )

        assert calls[0] == encoder.update_vault_state(harvest_params)

    async def test_below_min_assets_only_claims_exit_requests(self):
        # Earned below FEE_SPLITTER_MIN_ASSETS: no exit queue entry, but exited assets claimed.
        reward_splitter = create_reward_splitter(shareholders_earned_assets=[Wei(1)])
        encoder = RewardSplitterEncoder()
        exit_request = _claimable_exit_request()

        calls = await _get_reward_splitter_calls(
            reward_splitter=reward_splitter,
            harvest_params=None,
            exit_requests=[exit_request],
        )

        assert calls == [
            encoder.claim_exited_assets_on_behalf(
                position_ticket=exit_request.position_ticket,
                timestamp=exit_request.timestamp,
                exit_queue_index=exit_request.exit_queue_index,
            )
        ]


@pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
class TestClaimRewardSplittersForVault:
    async def test_returns_false_and_skips_send_on_high_gas(self):
        reward_splitter = create_reward_splitter(vault=ZERO_CHECKSUM_ADDRESS)

        with mock.patch(
            'src.reward_splitter.tasks.graph_get_reward_splitters',
            return_value=[reward_splitter],
        ), mock.patch(
            'src.reward_splitter.tasks.graph_get_claimable_exit_requests',
            return_value={},
        ), mock.patch(
            'src.reward_splitter.tasks.check_gas_price', return_value=False
        ), mock.patch(
            'src.reward_splitter.tasks.transaction_gas_wrapper'
        ) as tx_wrapper_mock, mock.patch(
            'src.reward_splitter.tasks.wallet', new=mock.MagicMock()
        ):
            succeeded = await claim_reward_splitters_for_vault(
                vault=ZERO_CHECKSUM_ADDRESS,
                block_number=Web3.to_int(1),
                harvest_params=None,
            )

        assert succeeded is False
        tx_wrapper_mock.assert_not_called()

    async def test_returns_true_when_no_splitters(self):
        with mock.patch(
            'src.reward_splitter.tasks.graph_get_reward_splitters', return_value=[]
        ), mock.patch('src.reward_splitter.tasks.wallet', new=mock.MagicMock()):
            succeeded = await claim_reward_splitters_for_vault(
                vault=ZERO_CHECKSUM_ADDRESS,
                block_number=Web3.to_int(1),
                harvest_params=None,
            )

        assert succeeded is True


@pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
class TestClaimRewardSplitters:
    async def test_advances_marker_only_when_all_succeeded(self):
        vaults = [faker.eth_address(), faker.eth_address()]

        with self._patch(per_vault_result=True) as (app_state, _):
            await claim_reward_splitters(vaults=vaults, update_vault_state=False)
            assert app_state.reward_splitter_block == 100

        with self._patch(per_vault_result=False) as (app_state, _):
            await claim_reward_splitters(vaults=vaults, update_vault_state=False)
            assert app_state.reward_splitter_block is None

    async def test_skips_when_interval_not_passed(self):
        with self._patch(per_vault_result=True, interval_passed=False) as (_, claim_mock):
            await claim_reward_splitters(vaults=[faker.eth_address()], update_vault_state=False)
            claim_mock.assert_not_called()

    def _patch(self, per_vault_result: bool, interval_passed: bool = True):
        from contextlib import contextmanager

        @contextmanager
        def ctx():
            app_state = mock.MagicMock()
            app_state.reward_splitter_block = None
            block = {'number': 100}
            with mock.patch(
                'src.reward_splitter.tasks.execution_client'
            ) as execution_client_mock, mock.patch(
                'src.reward_splitter.tasks.AppState', return_value=app_state
            ), mock.patch(
                'src.reward_splitter.tasks._check_reward_splitter_block',
                return_value=interval_passed,
            ), mock.patch(
                'src.reward_splitter.tasks.claim_reward_splitters_for_vault',
                return_value=per_vault_result,
            ) as claim_mock:
                execution_client_mock.eth.get_block = mock.AsyncMock(return_value=block)
                yield app_state, claim_mock

        return ctx()


def _harvest_params() -> HarvestParams:
    return HarvestParams(
        rewards_root=HexBytes(b'\x00' * 32),
        reward=Wei(0),
        unlocked_mev_reward=Wei(0),
        proof=[],
    )


def _claimable_exit_request() -> ExitRequest:
    return ExitRequest(
        vault=faker.eth_address(),
        position_ticket=1,
        timestamp=2,
        exit_queue_index=3,
        is_claimed=False,
        is_claimable=True,
        receiver=faker.eth_address(),
        exited_assets=Wei(0),
        total_assets=Wei(0),
    )
