from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_typing import ChecksumAddress, HexStr
from sw_utils.tests.factories import faker
from sw_utils.typings import ProtocolConfig
from web3 import Web3
from web3.types import Gwei, Wei

from src.common.tests.utils import ether_to_gwei
from src.node_manager.tasks import NodeManagerTask
from src.node_manager.typings import (
    EligibleOperator,
    NodeManagerApprovalRequest,
    NodeManagerRegistrationOraclesApproval,
)
from src.validators.typings import Validator

OPERATOR_ADDR: ChecksumAddress = faker.eth_address()
OTHER_ADDR: ChecksumAddress = faker.eth_address()

MODULE = 'src.node_manager.tasks'


@pytest.mark.usefixtures('fake_settings')
class TestProcessBlock:
    @pytest.mark.asyncio
    @patch(f'{MODULE}.check_gas_price', new_callable=AsyncMock, return_value=False)
    async def test_skips_when_gas_too_high(self, mock_gas: AsyncMock) -> None:
        task = _make_task()
        interrupt = MagicMock()

        await task.process_block(interrupt)

        mock_gas.assert_awaited_once_with(high_priority=True)

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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

    @pytest.mark.asyncio
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
            public_key=HexStr(faker.validator_public_key()),
            amount=ether_to_gwei(32),
            deposit_signature=HexStr(faker.validator_signature()),
        )
        mock_get_validators.return_value = [validator]

        request = MagicMock(spec=NodeManagerApprovalRequest)
        request.validators_root = HexStr(faker.merkle_root())
        request.validator_index = 0
        approval = MagicMock(spec=NodeManagerRegistrationOraclesApproval)
        mock_poll_reg.return_value = (request, approval)

        task = _make_task()
        await task.process_block(MagicMock())

        mock_register.assert_awaited_once()


@pytest.mark.usefixtures('fake_settings')
class TestProcessFunding:
    @pytest.mark.asyncio
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
    @pytest.mark.asyncio
    @patch(f'{MODULE}.get_deposits_amounts', return_value=[])
    async def test_no_amounts_skips(self, mock_deposits: MagicMock) -> None:
        task = _make_task()
        await task._process_registration(
            amount=Gwei(100),
            protocol_config=_make_protocol_config(),
        )

    @pytest.mark.asyncio
    @patch(f'{MODULE}.get_validators_for_registration', new_callable=AsyncMock, return_value=[])
    @patch(f'{MODULE}.get_deposits_amounts', return_value=[ether_to_gwei(32)])
    async def test_no_validators_skips(
        self,
        mock_deposits: MagicMock,
        mock_get_validators: AsyncMock,
    ) -> None:
        task = _make_task()
        await task._process_registration(
            amount=ether_to_gwei(32),
            protocol_config=_make_protocol_config(),
        )
        mock_get_validators.assert_awaited_once()


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
