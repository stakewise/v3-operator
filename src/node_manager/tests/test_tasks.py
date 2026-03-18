from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_typing import HexStr
from sw_utils.typings import ProtocolConfig
from web3 import Web3
from web3.types import Gwei, Wei

from src.node_manager.tasks import NodeManagerTask
from src.node_manager.typings import (
    EligibleOperator,
    NodeManagerApprovalRequest,
    NodeManagerRegistrationOraclesApproval,
)
from src.validators.typings import Validator

OPERATOR_ADDR = Web3.to_checksum_address('0x' + 'aa' * 20)
OTHER_ADDR = Web3.to_checksum_address('0x' + 'bb' * 20)

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
        """Operators not matching withdrawals_address are skipped."""
        mock_poll.return_value = [
            EligibleOperator(address=OTHER_ADDR, amount=Wei(32000000000000000000)),
        ]
        task = _make_task()
        await task.process_block(MagicMock())
        # _process_funding and _process_registration should not be called

    @pytest.mark.asyncio
    @patch(f'{MODULE}.register_validators', new_callable=AsyncMock, return_value='0xtxhash')
    @patch(f'{MODULE}.poll_registration_approval', new_callable=AsyncMock)
    @patch(f'{MODULE}.get_validators_for_registration', new_callable=AsyncMock)
    @patch(f'{MODULE}.get_deposits_amounts')
    @patch(f'{MODULE}.fetch_compounding_validators_balances', new_callable=AsyncMock)
    @patch(f'{MODULE}.poll_eligible_operators', new_callable=AsyncMock)
    @patch(f'{MODULE}.get_protocol_config', new_callable=AsyncMock)
    @patch(f'{MODULE}.check_gas_price', new_callable=AsyncMock, return_value=True)
    async def test_full_registration_flow(
        self,
        mock_gas: AsyncMock,
        mock_config: AsyncMock,
        mock_poll: AsyncMock,
        mock_balances: AsyncMock,
        mock_deposits: MagicMock,
        mock_get_validators: AsyncMock,
        mock_poll_reg: AsyncMock,
        mock_register: AsyncMock,
    ) -> None:
        """Full flow: eligible operator → no compounding → register new validators."""
        mock_config.return_value = _make_protocol_config()
        mock_poll.return_value = [
            EligibleOperator(address=OPERATOR_ADDR, amount=Wei(32000000000000000000)),
        ]
        mock_balances.return_value = {}  # no compounding validators
        mock_deposits.return_value = [Gwei(32000000000)]

        validator = Validator(
            public_key=HexStr('0x' + 'cc' * 48),
            amount=Gwei(32000000000),
            deposit_signature=HexStr('0x' + 'dd' * 96),
        )
        mock_get_validators.return_value = [validator]

        request = MagicMock(spec=NodeManagerApprovalRequest)
        request.validators_root = HexStr('0x' + 'ee' * 32)
        request.validator_index = 0
        approval = MagicMock(spec=NodeManagerRegistrationOraclesApproval)
        mock_poll_reg.return_value = (request, approval)

        task = _make_task()
        await task.process_block(MagicMock())

        mock_register.assert_awaited_once()


@pytest.mark.usefixtures('fake_settings')
class TestProcessFunding:
    @pytest.mark.asyncio
    @patch(f'{MODULE}.fetch_compounding_validators_balances', new_callable=AsyncMock)
    async def test_returns_full_amount_when_no_compounding(
        self,
        mock_balances: AsyncMock,
    ) -> None:
        mock_balances.return_value = {}
        task = _make_task()
        result = await task._process_funding(
            amount=Gwei(64000000000),
            operator_address=OPERATOR_ADDR,
            protocol_config=_make_protocol_config(),
        )
        assert result == Gwei(64000000000)

    @pytest.mark.asyncio
    @patch(f'{MODULE}.fund_validators', new_callable=AsyncMock, return_value='0xtx')
    @patch(f'{MODULE}.poll_funding_approval', new_callable=AsyncMock, return_value=b'\x00' * 65)
    @patch(f'{MODULE}.get_funding_amounts')
    @patch(f'{MODULE}.fetch_compounding_validators_balances', new_callable=AsyncMock)
    async def test_funds_and_returns_remainder(
        self,
        mock_balances: AsyncMock,
        mock_funding_amounts: MagicMock,
        mock_poll_funding: AsyncMock,
        mock_fund: AsyncMock,
    ) -> None:
        mock_balances.return_value = {HexStr('0x' + 'aa' * 48): Gwei(30000000000)}
        mock_funding_amounts.return_value = {HexStr('0x' + 'aa' * 48): Gwei(2000000000)}

        task = _make_task()
        result = await task._process_funding(
            amount=Gwei(10000000000),
            operator_address=OPERATOR_ADDR,
            protocol_config=_make_protocol_config(),
        )
        assert result == Gwei(10000000000 - 2000000000)

    @pytest.mark.asyncio
    @patch(f'{MODULE}.fund_validators', new_callable=AsyncMock, return_value=None)
    @patch(f'{MODULE}.poll_funding_approval', new_callable=AsyncMock, return_value=b'\x00' * 65)
    @patch(f'{MODULE}.get_funding_amounts')
    @patch(f'{MODULE}.fetch_compounding_validators_balances', new_callable=AsyncMock)
    async def test_stops_on_failed_tx(
        self,
        mock_balances: AsyncMock,
        mock_funding_amounts: MagicMock,
        mock_poll_funding: AsyncMock,
        mock_fund: AsyncMock,
    ) -> None:
        """When a funding tx fails, stop and return original amount."""
        mock_balances.return_value = {HexStr('0x' + 'aa' * 48): Gwei(30000000000)}
        mock_funding_amounts.return_value = {HexStr('0x' + 'aa' * 48): Gwei(2000000000)}

        task = _make_task()
        result = await task._process_funding(
            amount=Gwei(10000000000),
            operator_address=OPERATOR_ADDR,
            protocol_config=_make_protocol_config(),
        )
        # Failed tx means funded_total stays 0
        assert result == Gwei(10000000000)


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
    @patch(f'{MODULE}.get_deposits_amounts', return_value=[Gwei(32000000000)])
    async def test_no_validators_skips(
        self,
        mock_deposits: MagicMock,
        mock_get_validators: AsyncMock,
    ) -> None:
        task = _make_task()
        await task._process_registration(
            amount=Gwei(32000000000),
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
        withdrawals_address=OPERATOR_ADDR,
        keystore=keystore,
    )
