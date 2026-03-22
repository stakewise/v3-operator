from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_typing import ChecksumAddress, HexStr
from web3 import Web3
from web3.exceptions import ContractLogicError
from web3.types import Gwei

from src.node_manager.register_validators import (
    _submit_tx,
    fund_validators,
    register_validators,
)
from src.node_manager.typings import NodeManagerRegistrationOraclesApproval

MODULE = 'src.node_manager.register_validators'

OPERATOR_ADDR: ChecksumAddress = Web3.to_checksum_address('0x' + 'aa' * 20)


@pytest.mark.usefixtures('fake_settings')
class TestRegisterValidators:
    @pytest.mark.asyncio
    @patch(f'{MODULE}.get_validators_start_index', new_callable=AsyncMock, return_value=5)
    @patch(f'{MODULE}.validators_registry_contract')
    async def test_returns_none_on_root_change(
        self,
        mock_registry: MagicMock,
        mock_index: AsyncMock,
    ) -> None:
        """If registry root changed since approval, return None."""
        mock_registry.get_registry_root = AsyncMock(return_value=HexStr('0xnewroot'))

        result = await register_validators(
            withdrawals_address=OPERATOR_ADDR,
            approval=_make_approval(),
            validators=[],
            validators_registry_root=HexStr('0xoldroot'),
            validator_index=5,
        )
        assert result is None

    @pytest.mark.asyncio
    @patch(f'{MODULE}.get_validators_start_index', new_callable=AsyncMock, return_value=10)
    @patch(f'{MODULE}.validators_registry_contract')
    async def test_returns_none_on_index_change(
        self,
        mock_registry: MagicMock,
        mock_index: AsyncMock,
    ) -> None:
        """If validator index changed, return None."""
        root = HexStr('0x' + 'ab' * 32)
        mock_registry.get_registry_root = AsyncMock(return_value=root)

        result = await register_validators(
            withdrawals_address=OPERATOR_ADDR,
            approval=_make_approval(),
            validators=[],
            validators_registry_root=root,
            validator_index=5,  # doesn't match mock return of 10
        )
        assert result is None

    @pytest.mark.asyncio
    @patch(f'{MODULE}._submit_tx', new_callable=AsyncMock, return_value=HexStr('0xtxhash'))
    @patch(f'{MODULE}.encode_tx_validator_list', return_value=[b'\x00' * 100])
    @patch(f'{MODULE}.get_validators_start_index', new_callable=AsyncMock, return_value=5)
    @patch(f'{MODULE}.validators_registry_contract')
    async def test_success(
        self,
        mock_registry: MagicMock,
        mock_index: AsyncMock,
        mock_encode: MagicMock,
        mock_submit: AsyncMock,
    ) -> None:
        root = HexStr('0x' + 'ab' * 32)
        mock_registry.get_registry_root = AsyncMock(return_value=root)

        result = await register_validators(
            withdrawals_address=OPERATOR_ADDR,
            approval=_make_approval(),
            validators=[],
            validators_registry_root=root,
            validator_index=5,
        )
        assert result == HexStr('0xtxhash')
        mock_submit.assert_awaited_once()


@pytest.mark.usefixtures('fake_settings')
class TestFundValidators:
    @pytest.mark.asyncio
    @patch(f'{MODULE}._submit_tx', new_callable=AsyncMock, return_value=HexStr('0xfundtx'))
    @patch(f'{MODULE}.encode_tx_validator_list', return_value=[b'\x00' * 100])
    async def test_success(
        self,
        mock_encode: MagicMock,
        mock_submit: AsyncMock,
    ) -> None:
        fundings: dict[HexStr, Gwei] = {
            HexStr('0x' + 'aa' * 48): Gwei(2000000000),
        }
        result = await fund_validators(
            withdrawals_address=OPERATOR_ADDR,
            signatures=b'\x00' * 130,
            validator_fundings=fundings,
        )
        assert result == HexStr('0xfundtx')
        mock_submit.assert_awaited_once()


@pytest.mark.usefixtures('fake_settings')
class TestSubmitTx:
    @pytest.mark.asyncio
    @patch(f'{MODULE}.NodesManagerContract')
    async def test_gas_estimation_contract_error_returns_none(
        self,
        mock_contract_cls: MagicMock,
    ) -> None:
        contract = _mock_contract()
        mock_contract_cls.return_value = contract
        contract.functions.testFunc.return_value.estimate_gas = AsyncMock(
            side_effect=ContractLogicError('revert')
        )
        result = await _submit_tx('testFunc', (b'arg',), 'test action')
        assert result is None

    @pytest.mark.asyncio
    @patch(f'{MODULE}.NodesManagerContract')
    async def test_gas_estimation_value_error_returns_none(
        self,
        mock_contract_cls: MagicMock,
    ) -> None:
        contract = _mock_contract()
        mock_contract_cls.return_value = contract
        contract.functions.testFunc.return_value.estimate_gas = AsyncMock(
            side_effect=ValueError('insufficient funds')
        )
        result = await _submit_tx('testFunc', (b'arg',), 'test action')
        assert result is None

    @pytest.mark.asyncio
    @patch(f'{MODULE}.NodesManagerContract')
    async def test_successful_tx(
        self,
        mock_contract_cls: MagicMock,
    ) -> None:
        contract = _mock_contract()
        mock_contract_cls.return_value = contract

        gm = MagicMock()
        gm.get_high_priority_tx_params = AsyncMock(return_value={})

        mock_exec = MagicMock()
        mock_exec.eth.wait_for_transaction_receipt = AsyncMock(return_value={'status': 1})

        with (
            patch(f'{MODULE}.build_gas_manager', return_value=gm),
            patch(f'{MODULE}.execution_client', mock_exec),
        ):
            result = await _submit_tx('testFunc', (b'arg',), 'test action')

        assert result is not None

    @pytest.mark.asyncio
    @patch(f'{MODULE}.NodesManagerContract')
    async def test_failed_tx_receipt_returns_none(
        self,
        mock_contract_cls: MagicMock,
    ) -> None:
        contract = _mock_contract()
        mock_contract_cls.return_value = contract

        gm = MagicMock()
        gm.get_high_priority_tx_params = AsyncMock(return_value={})

        mock_exec = MagicMock()
        mock_exec.eth.wait_for_transaction_receipt = AsyncMock(return_value={'status': 0})

        with (
            patch(f'{MODULE}.build_gas_manager', return_value=gm),
            patch(f'{MODULE}.execution_client', mock_exec),
        ):
            result = await _submit_tx('testFunc', (b'arg',), 'test action')

        assert result is None

    @pytest.mark.asyncio
    @patch(f'{MODULE}.NodesManagerContract')
    async def test_transact_exception_returns_none(
        self,
        mock_contract_cls: MagicMock,
    ) -> None:
        contract = _mock_contract()
        mock_contract_cls.return_value = contract
        contract.functions.testFunc.return_value.transact = AsyncMock(
            side_effect=RuntimeError('nonce too low')
        )

        gm = MagicMock()
        gm.get_high_priority_tx_params = AsyncMock(return_value={})

        with patch(f'{MODULE}.build_gas_manager', return_value=gm):
            result = await _submit_tx('testFunc', (b'arg',), 'test action')

        assert result is None


def _make_approval() -> NodeManagerRegistrationOraclesApproval:
    return NodeManagerRegistrationOraclesApproval(
        keeper_signatures=b'\x01' * 65,
        nm_signatures=b'\x02' * 65,
        ipfs_hash='QmTest',
        deadline=1000,
    )


def _mock_contract() -> MagicMock:
    mock_fn = MagicMock()
    mock_fn.return_value.estimate_gas = AsyncMock()
    mock_fn.return_value.transact = AsyncMock(return_value=b'\x01' * 32)

    contract = MagicMock()
    contract.functions = MagicMock()
    setattr(contract.functions, 'testFunc', mock_fn)
    return contract
