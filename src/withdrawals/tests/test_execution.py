from unittest import mock

import pytest
from eth_typing import HexStr
from hexbytes import HexBytes
from web3 import Web3
from web3.exceptions import ContractCustomError
from web3.types import Gwei, Wei

from src.withdrawals.execution import _encode_withdrawals, submit_withdraw_validators

PUBLIC_KEY_1 = '0xb4e334000cd1991b0bcc3adddf2f6d3be32b737ab7728125033da35e9982112ec0a3d8a5a25a1858cf31d51b7305ce7a'
PUBLIC_KEY_2 = '0xa1e334000cd1991b0bcc3adddf2f6d3be32b737ab7728125033da35e9982112ec0a3d8a5a25a1858cf31d51b7305ce7b'


def test_encode_withdrawals():
    withdrawals = {
        '0xb4e334000cd1991b0bcc3adddf2f6d3be32b737ab7728125033da35e9982112ec0a3d8a5a25a1858cf31d51b7305ce7a': 1000
    }
    assert _encode_withdrawals(withdrawals) == Web3.to_bytes(
        hexstr='0xb4e334000cd1991b0bcc3adddf2f6d3be32b737ab7728125033da35e9982112ec0a3d8a5a25a1858cf31d51b7305ce7a00000000000003e8'
    )


def test_encode_withdrawals_concatenates_multiple_validators_in_dict_order():
    withdrawals = {
        PUBLIC_KEY_1: Gwei(1000),
        PUBLIC_KEY_2: Gwei(2000),
    }
    encoded = _encode_withdrawals(withdrawals)

    first_entry = Web3.to_bytes(hexstr=PUBLIC_KEY_1) + (1000).to_bytes(8, byteorder='big')
    second_entry = Web3.to_bytes(hexstr=PUBLIC_KEY_2) + (2000).to_bytes(8, byteorder='big')
    assert encoded == first_entry + second_entry


def test_encode_withdrawals_amount_zero_encodes_as_eight_zero_bytes():
    # amount=0 is EIP-7002 full-exit semantics, not an error
    withdrawals = {PUBLIC_KEY_1: Gwei(0)}

    encoded = _encode_withdrawals(withdrawals)

    assert encoded[48:] == b'\x00' * 8


def test_encode_withdrawals_large_amount_round_trips():
    amount_gwei = Gwei(2048 * 10**9)  # 2048 ETH, MAX_EFFECTIVE_BALANCE_ELECTRA
    withdrawals = {PUBLIC_KEY_1: amount_gwei}

    encoded = _encode_withdrawals(withdrawals)

    assert int.from_bytes(encoded[48:56], byteorder='big') == amount_gwei


def test_encode_withdrawals_total_length_is_56_bytes_per_validator():
    withdrawals = {
        PUBLIC_KEY_1: Gwei(1),
        PUBLIC_KEY_2: Gwei(2),
    }

    encoded = _encode_withdrawals(withdrawals)

    assert len(encoded) == 56 * len(withdrawals)


@pytest.mark.usefixtures('fake_settings')
class TestSubmitWithdrawValidators:
    withdrawals = {PUBLIC_KEY_1: Gwei(1000)}
    tx_fee = Wei(123)
    signature = HexStr('0x' + '11' * 65)

    async def test_success_returns_tx_hash_and_passes_tx_fee_as_value(self):
        tx_hash = HexBytes('0xab')
        transact = mock.AsyncMock(return_value={'transactionHash': tx_hash})
        vault_contract = _mock_vault_contract()

        with _patch(vault_contract=vault_contract, transact=transact):
            result = await submit_withdraw_validators(self.withdrawals, self.tx_fee, self.signature)

        assert result == Web3.to_hex(tx_hash)
        assert transact.call_args.kwargs['tx_params'] == {'value': self.tx_fee}
        vault_contract.functions.withdrawValidators.assert_called_once_with(
            _encode_withdrawals(self.withdrawals),
            Web3.to_bytes(hexstr=self.signature),
        )

    async def test_contract_custom_error_returns_none_without_raising(self):
        transact = mock.AsyncMock(side_effect=ContractCustomError('reverted', data='0xdeadbeef'))
        vault_contract = _mock_vault_contract(decoded_error='InvalidValidators()')

        with _patch(vault_contract=vault_contract, transact=transact):
            result = await submit_withdraw_validators(self.withdrawals, self.tx_fee, self.signature)

        assert result is None
        vault_contract.decode_custom_error.assert_called_once_with('0xdeadbeef')

    async def test_generic_exception_returns_none_without_raising(self):
        transact = mock.AsyncMock(side_effect=ValueError('boom'))
        vault_contract = _mock_vault_contract()

        with _patch(vault_contract=vault_contract, transact=transact):
            result = await submit_withdraw_validators(self.withdrawals, self.tx_fee, self.signature)

        assert result is None

    async def test_none_tx_receipt_returns_none(self):
        # tx_manager.transact already returns None on a failed/timed-out receipt
        transact = mock.AsyncMock(return_value=None)
        vault_contract = _mock_vault_contract()

        with _patch(vault_contract=vault_contract, transact=transact):
            result = await submit_withdraw_validators(self.withdrawals, self.tx_fee, self.signature)

        assert result is None


def _mock_vault_contract(decoded_error: str | None = None) -> mock.Mock:
    vault_contract = mock.Mock()
    vault_contract.functions.withdrawValidators = mock.Mock(return_value=mock.Mock())
    vault_contract.decode_custom_error = mock.Mock(return_value=decoded_error)
    return vault_contract


def _patch(vault_contract: mock.Mock, transact: mock.AsyncMock):
    return mock.patch.multiple(
        'src.withdrawals.execution',
        VaultContract=mock.Mock(return_value=vault_contract),
        tx_manager=mock.Mock(transact=transact),
    )
