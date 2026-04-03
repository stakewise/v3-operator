from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_typing import ChecksumAddress
from hexbytes import HexBytes
from sw_utils.tests.factories import faker
from sw_utils.typings import ProtocolConfig
from web3 import Web3
from web3.types import Gwei, Wei

from src.common.app_state import AppState
from src.common.tests.utils import ether_to_gwei
from src.common.typings import HarvestParams
from src.config.settings import settings
from src.node_manager.tasks import NodeManagerTask, StateSyncTask
from src.node_manager.typings import (
    EligibleOperator,
    NodeManagerApprovalRequest,
    NodeManagerRegistrationOraclesApproval,
    OperatorStateUpdateParams,
)
from src.validators.typings import Validator

OPERATOR_ADDR: ChecksumAddress = faker.eth_address()
OTHER_ADDR: ChecksumAddress = faker.eth_address()

MODULE = 'src.node_manager.tasks'


@pytest.mark.usefixtures('fake_settings')
class TestProcessBlock:
    @patch(f'{MODULE}.check_gas_price', new_callable=AsyncMock, return_value=False)
    async def test_skips_when_gas_too_high(self, mock_gas: AsyncMock) -> None:
        task = _make_task()
        interrupt = MagicMock()

        await task.process_block(interrupt)

        mock_gas.assert_awaited_once_with(high_priority=True)

    @patch(f'{MODULE}.poll_eligible_operators', new_callable=AsyncMock, return_value=[])
    @patch(f'{MODULE}.get_protocol_config', new_callable=AsyncMock)
    @patch(f'{MODULE}.check_gas_price', new_callable=AsyncMock, return_value=True)
    async def test_no_eligible_operators(
        self,
        mock_gas: AsyncMock,
        mock_config: AsyncMock,
        mock_poll: AsyncMock,
    ) -> None:
        task = _make_task()
        await task.process_block(MagicMock())
        mock_poll.assert_awaited_once()

    @patch(f'{MODULE}.poll_eligible_operators', new_callable=AsyncMock)
    @patch(f'{MODULE}.get_protocol_config', new_callable=AsyncMock)
    @patch(f'{MODULE}.check_gas_price', new_callable=AsyncMock, return_value=True)
    async def test_skips_other_operator(
        self,
        mock_gas: AsyncMock,
        mock_config: AsyncMock,
        mock_poll: AsyncMock,
    ) -> None:
        """Operators not matching operator_address are skipped."""
        mock_config.return_value = _make_protocol_config()
        mock_poll.return_value = [
            EligibleOperator(address=OTHER_ADDR, amount=Wei(Web3.to_wei(32, 'ether'))),
        ]
        task = _make_task()
        await task.process_block(MagicMock())
        # Should not proceed to registration for other operator
        mock_poll.assert_awaited_once()

    @patch(f'{MODULE}.register_validators', new_callable=AsyncMock, return_value='0xtxhash')
    @patch(f'{MODULE}.poll_registration_approval', new_callable=AsyncMock)
    @patch(f'{MODULE}.get_validators_for_registration', new_callable=AsyncMock)
    @patch(f'{MODULE}.get_deposits_amounts')
    @patch(f'{MODULE}.poll_eligible_operators', new_callable=AsyncMock)
    @patch(f'{MODULE}.get_protocol_config', new_callable=AsyncMock)
    @patch(f'{MODULE}.check_gas_price', new_callable=AsyncMock, return_value=True)
    async def test_full_registration_flow(
        self,
        mock_gas: AsyncMock,
        mock_config: AsyncMock,
        mock_poll: AsyncMock,
        mock_deposits: MagicMock,
        mock_get_validators: AsyncMock,
        mock_poll_reg: AsyncMock,
        mock_register: AsyncMock,
    ) -> None:
        """Full flow: eligible operator → stub funding → register new validators."""
        mock_config.return_value = _make_protocol_config()
        mock_poll.return_value = [
            EligibleOperator(address=OPERATOR_ADDR, amount=Wei(Web3.to_wei(32, 'ether'))),
        ]
        mock_deposits.return_value = [ether_to_gwei(32)]

        validator = Validator(
            public_key=faker.validator_public_key(),
            amount=ether_to_gwei(32),
            deposit_signature=faker.validator_signature(),
        )
        mock_get_validators.return_value = [validator]

        request = MagicMock(spec=NodeManagerApprovalRequest)
        request.validators_root = faker.merkle_root()
        request.validator_index = 0
        approval = MagicMock(spec=NodeManagerRegistrationOraclesApproval)
        mock_poll_reg.return_value = (request, approval)

        task = _make_task()
        await task.process_block(MagicMock())

        mock_register.assert_awaited_once()


@pytest.mark.usefixtures('fake_settings')
class TestProcessBlockDisableFlags:
    """Tests for disable_validators_funding and disable_validators_registration flags."""

    @patch(f'{MODULE}.register_validators', new_callable=AsyncMock)
    @patch(f'{MODULE}.get_deposits_amounts', return_value=[])
    @patch(f'{MODULE}.poll_eligible_operators', new_callable=AsyncMock)
    @patch(f'{MODULE}.get_protocol_config', new_callable=AsyncMock)
    @patch(f'{MODULE}.check_gas_price', new_callable=AsyncMock, return_value=True)
    async def test_disable_funding_skips_to_registration(
        self,
        mock_gas: AsyncMock,
        mock_config: AsyncMock,
        mock_poll: AsyncMock,
        mock_deposits: MagicMock,
        mock_register: AsyncMock,
    ) -> None:
        """With disable_validators_funding, skips funding but still tries registration."""
        settings.disable_validators_funding = True
        mock_config.return_value = _make_protocol_config()
        mock_poll.return_value = [
            EligibleOperator(address=OPERATOR_ADDR, amount=Wei(Web3.to_wei(32, 'ether'))),
        ]

        task = _make_task()
        await task.process_block(MagicMock())

        # Registration path was entered (get_deposits_amounts called with original amount)
        mock_deposits.assert_called_once()

    @patch(f'{MODULE}.register_validators', new_callable=AsyncMock)
    @patch(f'{MODULE}.get_deposits_amounts')
    @patch(f'{MODULE}.poll_eligible_operators', new_callable=AsyncMock)
    @patch(f'{MODULE}.get_protocol_config', new_callable=AsyncMock)
    @patch(f'{MODULE}.check_gas_price', new_callable=AsyncMock, return_value=True)
    async def test_disable_registration_skips_registration(
        self,
        mock_gas: AsyncMock,
        mock_config: AsyncMock,
        mock_poll: AsyncMock,
        mock_deposits: MagicMock,
        mock_register: AsyncMock,
    ) -> None:
        """With disable_validators_registration, skips registration after funding."""
        settings.disable_validators_registration = True
        mock_config.return_value = _make_protocol_config()
        mock_poll.return_value = [
            EligibleOperator(address=OPERATOR_ADDR, amount=Wei(Web3.to_wei(32, 'ether'))),
        ]

        task = _make_task()
        await task.process_block(MagicMock())

        mock_deposits.assert_not_called()
        mock_register.assert_not_awaited()


@pytest.mark.usefixtures('fake_settings')
class TestProcessFunding:
    async def test_stub_returns_full_amount(self) -> None:
        """Current stub _process_funding returns full amount unchanged."""
        task = _make_task()
        result = await task._process_funding(
            amount=Gwei(64000000000),
            operator_address=OPERATOR_ADDR,
            protocol_config=_make_protocol_config(),
        )
        assert result == Gwei(64000000000)


@pytest.mark.usefixtures('fake_settings')
class TestProcessRegistration:
    @patch(f'{MODULE}.register_validators', new_callable=AsyncMock)
    @patch(f'{MODULE}.get_deposits_amounts', return_value=[])
    async def test_no_amounts_skips(
        self,
        mock_deposits: MagicMock,
        mock_register: AsyncMock,
    ) -> None:
        task = _make_task()
        await task._process_registration(
            amount=Gwei(100),
            protocol_config=_make_protocol_config(),
        )
        mock_register.assert_not_awaited()

    @patch(f'{MODULE}.register_validators', new_callable=AsyncMock)
    @patch(f'{MODULE}.get_validators_for_registration', new_callable=AsyncMock, return_value=[])
    @patch(f'{MODULE}.get_deposits_amounts', return_value=[ether_to_gwei(32)])
    async def test_no_validators_skips(
        self,
        mock_deposits: MagicMock,
        mock_get_validators: AsyncMock,
        mock_register: AsyncMock,
    ) -> None:
        task = _make_task()
        await task._process_registration(
            amount=ether_to_gwei(32),
            protocol_config=_make_protocol_config(),
        )
        mock_get_validators.assert_awaited_once()
        mock_register.assert_not_awaited()

    @patch(f'{MODULE}.register_validators', new_callable=AsyncMock)
    @patch(f'{MODULE}.get_validators_for_registration', new_callable=AsyncMock, return_value=[])
    @patch(f'{MODULE}.get_deposits_amounts')
    async def test_amounts_truncated_to_batch_limit(
        self,
        mock_deposits: MagicMock,
        mock_get_validators: AsyncMock,
        mock_register: AsyncMock,
    ) -> None:
        """Amounts list is truncated to validators_approval_batch_limit."""
        mock_deposits.return_value = [ether_to_gwei(32)] * 5

        config = _make_protocol_config()
        config.validators_approval_batch_limit = 2

        task = _make_task()
        await task._process_registration(
            amount=ether_to_gwei(160),
            protocol_config=config,
        )
        # get_validators_for_registration receives only 2 amounts (truncated from 5)
        call_args = mock_get_validators.call_args
        amounts_arg = call_args.kwargs.get(
            'amounts', call_args.args[1] if len(call_args.args) > 1 else None
        )
        assert len(amounts_arg) == 2
        mock_register.assert_not_awaited()


@pytest.mark.usefixtures('fake_settings')
class TestStateSyncProcessBlock:
    """Tests for StateSyncTask.process_block."""

    @patch(f'{MODULE}.NodesManagerContract')
    async def test_skips_when_already_synced(
        self,
        mock_nm_cls: MagicMock,
    ) -> None:
        """Returns early when operator nonce matches current nonce."""
        nm_instance = mock_nm_cls.return_value
        nm_instance.get_state_data = AsyncMock(return_value=(b'', 0, 0, 5))
        nm_instance.get_operator_last_state_nonce = AsyncMock(return_value=5)

        task = StateSyncTask(operator_address=OPERATOR_ADDR)
        await task.process_block(MagicMock())

        nm_instance.get_state_data.assert_awaited_once()
        nm_instance.get_operator_last_state_nonce.assert_awaited_once_with(OPERATOR_ADDR)
        nm_instance.get_last_state_updated_event.assert_not_called()

    @patch(f'{MODULE}.NodesManagerContract')
    async def test_skips_when_no_event(
        self,
        mock_nm_cls: MagicMock,
    ) -> None:
        """Returns early when no StateUpdated event is found."""
        nm_instance = mock_nm_cls.return_value
        nm_instance.get_state_data = AsyncMock(return_value=(b'', 0, 0, 5))
        nm_instance.get_operator_last_state_nonce = AsyncMock(return_value=3)
        nm_instance.execution_client = MagicMock()
        nm_instance.execution_client.eth.get_block_number = AsyncMock(return_value=100)
        nm_instance.get_last_state_updated_event = AsyncMock(return_value=None)

        task = StateSyncTask(operator_address=OPERATOR_ADDR)
        await task.process_block(MagicMock())

        nm_instance.get_last_state_updated_event.assert_awaited_once()

    @patch(f'{MODULE}.fetch_operator_state_from_ipfs', new_callable=AsyncMock, return_value=None)
    @patch(f'{MODULE}.NodesManagerContract')
    async def test_skips_when_operator_not_in_ipfs(
        self,
        mock_nm_cls: MagicMock,
        mock_fetch: AsyncMock,
    ) -> None:
        """Returns early when operator is not found in IPFS data."""
        _setup_nm_contract(mock_nm_cls)

        task = StateSyncTask(operator_address=OPERATOR_ADDR)
        await task.process_block(MagicMock())

        mock_fetch.assert_awaited_once_with('QmTestHash', OPERATOR_ADDR)

    @patch(f'{MODULE}.check_gas_price', new_callable=AsyncMock, return_value=False)
    @patch(f'{MODULE}.fetch_operator_state_from_ipfs', new_callable=AsyncMock)
    @patch(f'{MODULE}.NodesManagerContract')
    async def test_skips_when_gas_too_high(
        self,
        mock_nm_cls: MagicMock,
        mock_fetch: AsyncMock,
        mock_gas: AsyncMock,
    ) -> None:
        """Returns early when gas price is too high."""
        _setup_nm_contract(mock_nm_cls)
        mock_fetch.return_value = _make_operator_params()

        task = StateSyncTask(operator_address=OPERATOR_ADDR)
        await task.process_block(MagicMock())

        mock_gas.assert_awaited_once()

    @patch(f'{MODULE}.submit_state_sync_transaction', new_callable=AsyncMock, return_value='0xabc')
    @patch(f'{MODULE}.keeper_contract')
    @patch(f'{MODULE}.check_gas_price', new_callable=AsyncMock, return_value=True)
    @patch(f'{MODULE}.fetch_operator_state_from_ipfs', new_callable=AsyncMock)
    @patch(f'{MODULE}.NodesManagerContract')
    async def test_submits_without_harvest(
        self,
        mock_nm_cls: MagicMock,
        mock_fetch: AsyncMock,
        mock_gas: AsyncMock,
        mock_keeper: MagicMock,
        mock_submit: AsyncMock,
    ) -> None:
        """Submits state sync without harvest params when vault cannot harvest."""
        _setup_nm_contract(mock_nm_cls)
        operator_params = _make_operator_params()
        mock_fetch.return_value = operator_params
        mock_keeper.can_harvest = AsyncMock(return_value=False)

        task = StateSyncTask(operator_address=OPERATOR_ADDR)
        await task.process_block(MagicMock())

        mock_submit.assert_awaited_once_with(
            operator_address=OPERATOR_ADDR,
            params=operator_params,
            harvest_params=None,
        )

    @patch(f'{MODULE}.submit_state_sync_transaction', new_callable=AsyncMock, return_value='0xabc')
    @patch(f'{MODULE}.get_harvest_params', new_callable=AsyncMock)
    @patch(f'{MODULE}.keeper_contract')
    @patch(f'{MODULE}.check_gas_price', new_callable=AsyncMock, return_value=True)
    @patch(f'{MODULE}.fetch_operator_state_from_ipfs', new_callable=AsyncMock)
    @patch(f'{MODULE}.NodesManagerContract')
    async def test_submits_with_harvest(
        self,
        mock_nm_cls: MagicMock,
        mock_fetch: AsyncMock,
        mock_gas: AsyncMock,
        mock_keeper: MagicMock,
        mock_harvest: AsyncMock,
        mock_submit: AsyncMock,
    ) -> None:
        """Submits state sync with harvest params when vault can harvest."""
        _setup_nm_contract(mock_nm_cls)
        operator_params = _make_operator_params()
        mock_fetch.return_value = operator_params
        mock_keeper.can_harvest = AsyncMock(return_value=True)
        harvest_params = MagicMock(spec=HarvestParams)
        mock_harvest.return_value = harvest_params

        task = StateSyncTask(operator_address=OPERATOR_ADDR)
        await task.process_block(MagicMock())

        mock_submit.assert_awaited_once_with(
            operator_address=OPERATOR_ADDR,
            params=operator_params,
            harvest_params=harvest_params,
        )

    @patch(f'{MODULE}.submit_state_sync_transaction', new_callable=AsyncMock)
    @patch(f'{MODULE}.get_harvest_params', new_callable=AsyncMock, return_value=None)
    @patch(f'{MODULE}.keeper_contract')
    @patch(f'{MODULE}.check_gas_price', new_callable=AsyncMock, return_value=True)
    @patch(f'{MODULE}.fetch_operator_state_from_ipfs', new_callable=AsyncMock)
    @patch(f'{MODULE}.NodesManagerContract')
    async def test_skips_when_harvest_params_unavailable(
        self,
        mock_nm_cls: MagicMock,
        mock_fetch: AsyncMock,
        mock_gas: AsyncMock,
        mock_keeper: MagicMock,
        mock_harvest: AsyncMock,
        mock_submit: AsyncMock,
    ) -> None:
        """Returns early when vault needs harvesting but params are unavailable."""
        _setup_nm_contract(mock_nm_cls)
        mock_fetch.return_value = _make_operator_params()
        mock_keeper.can_harvest = AsyncMock(return_value=True)

        task = StateSyncTask(operator_address=OPERATOR_ADDR)
        await task.process_block(MagicMock())

        mock_submit.assert_not_awaited()

    @patch(f'{MODULE}.submit_state_sync_transaction', new_callable=AsyncMock, return_value='0xabc')
    @patch(f'{MODULE}.keeper_contract')
    @patch(f'{MODULE}.check_gas_price', new_callable=AsyncMock, return_value=True)
    @patch(f'{MODULE}.fetch_operator_state_from_ipfs', new_callable=AsyncMock)
    @patch(f'{MODULE}.NodesManagerContract')
    async def test_updates_state_sync_block_checkpoint(
        self,
        mock_nm_cls: MagicMock,
        mock_fetch: AsyncMock,
        mock_gas: AsyncMock,
        mock_keeper: MagicMock,
        mock_submit: AsyncMock,
    ) -> None:
        """AppState.state_sync_block is updated to the event's block number."""
        _setup_nm_contract(mock_nm_cls, event_block_number=42)
        mock_fetch.return_value = _make_operator_params()
        mock_keeper.can_harvest = AsyncMock(return_value=False)

        task = StateSyncTask(operator_address=OPERATOR_ADDR)
        await task.process_block(MagicMock())

        app_state = AppState()
        assert app_state.state_sync_block == 42


def _setup_nm_contract(
    mock_nm_cls: MagicMock,
    current_nonce: int = 5,
    operator_nonce: int = 3,
    event_block_number: int = 100,
) -> MagicMock:
    """Configure a mock NodesManagerContract with common defaults."""
    nm_instance = mock_nm_cls.return_value
    nm_instance.get_state_data = AsyncMock(return_value=(b'', 0, 0, current_nonce))
    nm_instance.get_operator_last_state_nonce = AsyncMock(return_value=operator_nonce)
    nm_instance.execution_client = MagicMock()
    nm_instance.execution_client.eth.get_block_number = AsyncMock(return_value=200)
    nm_instance.get_last_state_updated_event = AsyncMock(
        return_value={
            'blockNumber': event_block_number,
            'args': {'stateIpfsHash': 'QmTestHash'},
        }
    )
    return nm_instance


def _make_operator_params() -> OperatorStateUpdateParams:
    return OperatorStateUpdateParams(
        total_assets=1000,
        cum_penalty_assets=0,
        cum_earned_fee_shares=500,
        proof=[HexBytes(b'\x01' * 32)],
    )


def _make_protocol_config() -> MagicMock:
    config = MagicMock(spec=ProtocolConfig)
    config.validators_approval_batch_limit = 10
    return config


def _make_task() -> NodeManagerTask:
    keystore = MagicMock()
    return NodeManagerTask(
        operator_address=OPERATOR_ADDR,
        keystore=keystore,
    )
