from web3 import Web3

from src.withdrawals.execution import _encode_withdrawals


def test_encode_withdrawals():
    withdrawals = {
        '0xb4e334000cd1991b0bcc3adddf2f6d3be32b737ab7728125033da35e9982112ec0a3d8a5a25a1858cf31d51b7305ce7a': 1000
    }
    assert _encode_withdrawals(withdrawals) == Web3.to_bytes(
        hexstr='0xb4e334000cd1991b0bcc3adddf2f6d3be32b737ab7728125033da35e9982112ec0a3d8a5a25a1858cf31d51b7305ce7a00000000000003e8'
    )
