from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_typing import ChecksumAddress
from sw_utils.tests.factories import faker
from web3 import Web3
from web3.exceptions import ContractLogicError

from src.common.tests.utils import ether_to_gwei
from src.node_manager.register_validators import fund_validators, register_validators
from src.node_manager.typings import NodeManagerRegistrationOraclesApproval
from src.validators.typings import Validator

MODULE = 'src.node_manager.register_validators'

OPERATOR_ADDR: ChecksumAddress = faker.eth_address()


@pytest.mark.usefixtures('fake_settings')
class TestRegisterValidators:
    @patch(f'{MODULE}.get_validators_start_index', new_callable=AsyncMock, return_value=5)
    @patch(f'{MODULE}.validators_registry_contract')
    async def test_returns_none_on_root_change(
        self,
        mock_registry: MagicMock,
        mock_index: AsyncMock,
    ) -> None:
        """If registry root changed since approval, return None."""
        mock_registry.get_registry_root = AsyncMock(return_value=faker.merkle_root())

        result = await register_validators(
            operator_address=OPERATOR_ADDR,
            approval=_make_approval(),
            validators=[],
            validators_registry_root=faker.merkle_root(),
            validator_index=5,
        )
        assert result is None

    @patch(f'{MODULE}.get_validators_start_index', new_callable=AsyncMock, return_value=10)
    @patch(f'{MODULE}.validators_registry_contract')
    async def test_returns_none_on_index_change(
        self,
        mock_registry: MagicMock,
        mock_index: AsyncMock,
    ) -> None:
        """If validator index changed, return None."""
        root = faker.merkle_root()
        mock_registry.get_registry_root = AsyncMock(return_value=root)

        result = await register_validators(
            operator_address=OPERATOR_ADDR,
            approval=_make_approval(),
            validators=[],
            validators_registry_root=root,
            validator_index=5,  # doesn't match mock return of 10
        )
        assert result is None

    @patch(f'{MODULE}.encode_tx_validator_list', return_value=[b'\x00' * 100])
    @patch(f'{MODULE}.get_validators_start_index', new_callable=AsyncMock, return_value=5)
    @patch(f'{MODULE}.validators_registry_contract')
    async def test_success(
        self,
        mock_registry: MagicMock,
        mock_index: AsyncMock,
        mock_encode: MagicMock,
    ) -> None:
        root = faker.merkle_root()
        mock_registry.get_registry_root = AsyncMock(return_value=root)
        approval = _make_approval()

        mock_fn = MagicMock()
        mock_fn.return_value.estimate_gas = AsyncMock()
        mock_fn.return_value.transact = AsyncMock(return_value=b'\x01' * 32)

        mock_contract = MagicMock()
        mock_contract.functions.registerValidators = mock_fn

        gm = MagicMock()
        gm.get_high_priority_tx_params = AsyncMock(return_value={})

        mock_exec = MagicMock()
        mock_exec.eth.wait_for_transaction_receipt = AsyncMock(return_value={'status': 1})

        with (
            patch(f'{MODULE}.nodes_manager_contract', mock_contract),
            patch(f'{MODULE}.build_gas_manager', return_value=gm),
            patch(f'{MODULE}.execution_client', mock_exec),
        ):
            result = await register_validators(
                operator_address=OPERATOR_ADDR,
                approval=approval,
                validators=[],
                validators_registry_root=root,
                validator_index=5,
            )
        assert result is not None

        expected_signatures = b''.join(
            Web3.to_bytes(hexstr=s) for s in approval.nodes_manager_signatures
        )
        expected_keeper_params = (
            Web3.to_bytes(hexstr=root),
            approval.deadline,
            b''.join(Web3.to_bytes(v) for v in mock_encode.return_value),
            b''.join(Web3.to_bytes(hexstr=s) for s in approval.keeper_signatures),
            approval.ipfs_hash,
        )
        mock_fn.assert_called_with(OPERATOR_ADDR, expected_keeper_params, expected_signatures)

    @patch(f'{MODULE}.encode_tx_validator_list', return_value=[b'\x00' * 100])
    @patch(f'{MODULE}.get_validators_start_index', new_callable=AsyncMock, return_value=5)
    @patch(f'{MODULE}.validators_registry_contract')
    async def test_gas_estimation_error_returns_none(
        self,
        mock_registry: MagicMock,
        mock_index: AsyncMock,
        mock_encode: MagicMock,
    ) -> None:
        root = faker.merkle_root()
        mock_registry.get_registry_root = AsyncMock(return_value=root)

        mock_fn = MagicMock()
        mock_fn.return_value.estimate_gas = AsyncMock(side_effect=ContractLogicError('revert'))

        mock_contract = MagicMock()
        mock_contract.functions.registerValidators = mock_fn

        with patch(f'{MODULE}.nodes_manager_contract', mock_contract):
            result = await register_validators(
                operator_address=OPERATOR_ADDR,
                approval=_make_approval(),
                validators=[],
                validators_registry_root=root,
                validator_index=5,
            )
        assert result is None

    @patch(f'{MODULE}.encode_tx_validator_list', return_value=[b'\x00' * 100])
    @patch(f'{MODULE}.get_validators_start_index', new_callable=AsyncMock, return_value=5)
    @patch(f'{MODULE}.validators_registry_contract')
    async def test_failed_tx_receipt_returns_none(
        self,
        mock_registry: MagicMock,
        mock_index: AsyncMock,
        mock_encode: MagicMock,
    ) -> None:
        root = faker.merkle_root()
        mock_registry.get_registry_root = AsyncMock(return_value=root)

        mock_fn = MagicMock()
        mock_fn.return_value.estimate_gas = AsyncMock()
        mock_fn.return_value.transact = AsyncMock(return_value=b'\x01' * 32)

        mock_contract = MagicMock()
        mock_contract.functions.registerValidators = mock_fn

        gm = MagicMock()
        gm.get_high_priority_tx_params = AsyncMock(return_value={})

        mock_exec = MagicMock()
        mock_exec.eth.wait_for_transaction_receipt = AsyncMock(return_value={'status': 0})

        with (
            patch(f'{MODULE}.nodes_manager_contract', mock_contract),
            patch(f'{MODULE}.build_gas_manager', return_value=gm),
            patch(f'{MODULE}.execution_client', mock_exec),
        ):
            result = await register_validators(
                operator_address=OPERATOR_ADDR,
                approval=_make_approval(),
                validators=[],
                validators_registry_root=root,
                validator_index=5,
            )
        assert result is None


@pytest.mark.usefixtures('fake_settings')
class TestFundValidators:
    @patch(f'{MODULE}.encode_tx_validator_list', return_value=[b'\x00' * 100])
    async def test_success(
        self,
        mock_encode: MagicMock,
    ) -> None:
        mock_exec = MagicMock()
        mock_exec.eth.wait_for_transaction_receipt = AsyncMock(return_value={'status': 1})

        with (
            patch(f'{MODULE}.nodes_manager_contract', MagicMock()),
            patch(
                f'{MODULE}.transaction_gas_wrapper',
                new_callable=AsyncMock,
                return_value=b'\x01' * 32,
            ),
            patch(f'{MODULE}.execution_client', mock_exec),
        ):
            result = await fund_validators(
                operator_address=OPERATOR_ADDR,
                signatures=[faker.account_signature()],
                validators=_make_validators(),
            )
        assert result is not None

    @patch(f'{MODULE}.encode_tx_validator_list', return_value=[b'\x00' * 100])
    async def test_transaction_error_returns_none(
        self,
        mock_encode: MagicMock,
    ) -> None:
        with patch(
            f'{MODULE}.transaction_gas_wrapper',
            new_callable=AsyncMock,
            side_effect=Exception('tx failed'),
        ):
            result = await fund_validators(
                operator_address=OPERATOR_ADDR,
                signatures=[faker.account_signature()],
                validators=_make_validators(),
            )
        assert result is None

    @patch(f'{MODULE}.encode_tx_validator_list', return_value=[b'\x00' * 100])
    async def test_failed_tx_receipt_returns_none(
        self,
        mock_encode: MagicMock,
    ) -> None:
        mock_exec = MagicMock()
        mock_exec.eth.wait_for_transaction_receipt = AsyncMock(return_value={'status': 0})

        with (
            patch(
                f'{MODULE}.transaction_gas_wrapper',
                new_callable=AsyncMock,
                return_value=b'\x01' * 32,
            ),
            patch(f'{MODULE}.execution_client', mock_exec),
        ):
            result = await fund_validators(
                operator_address=OPERATOR_ADDR,
                signatures=[faker.account_signature()],
                validators=_make_validators(),
            )
        assert result is None


def _make_validators() -> list[Validator]:
    return [
        Validator(
            public_key=faker.validator_public_key(),
            amount=ether_to_gwei(32),
            deposit_signature=faker.validator_signature(),
        )
    ]


def _make_approval() -> NodeManagerRegistrationOraclesApproval:
    return NodeManagerRegistrationOraclesApproval(
        keeper_signatures=[faker.account_signature()],
        nodes_manager_signatures=[faker.account_signature()],
        ipfs_hash=faker.ipfs_hash(),
        deadline=1000,
    )
