from eth_abi import abi as eth_abi
from eth_utils import function_signature_to_4byte_selector

from src.common.contracts import VaultContract, decode_custom_error
from src.config.networks import ZERO_CHECKSUM_ADDRESS


def _encode_error(signature: str, arg_types: list[str], args: list) -> str:
    selector = function_signature_to_4byte_selector(signature)
    payload = selector + (eth_abi.encode(arg_types, args) if arg_types else b'')
    return '0x' + payload.hex()


class TestDecodeCustomError:
    error_abi = VaultContract(address=ZERO_CHECKSUM_ADDRESS).error_abi

    def test_abi_error_without_args(self) -> None:
        data = _encode_error('AccessDenied()', [], [])
        assert decode_custom_error(self.error_abi, data) == 'AccessDenied()'

    def test_abi_error_with_args(self) -> None:
        data = _encode_error('InsufficientBalance(uint256,uint256)', ['uint256', 'uint256'], [3, 7])
        assert (
            decode_custom_error(self.error_abi, data) == 'InsufficientBalance(balance=3, needed=7)'
        )

    def test_stakewise_library_error(self) -> None:
        # InvalidValidators is reverted from the Errors library and is absent
        # from the vault ABI, so it is resolved via the merged error ABI.
        data = _encode_error('InvalidValidators()', [], [])
        assert decode_custom_error(self.error_abi, data) == 'InvalidValidators()'

    def test_unknown_selector_returns_none(self) -> None:
        assert decode_custom_error(self.error_abi, '0xdeadbeef') is None

    def test_invalid_inputs_return_none(self) -> None:
        assert decode_custom_error(self.error_abi, str(None)) is None
        assert decode_custom_error(self.error_abi, '0x1234') is None
        assert decode_custom_error(self.error_abi, 'not-hex') is None
