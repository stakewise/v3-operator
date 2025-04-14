import json
import logging
from pathlib import Path

from eth_typing import HexAddress
from eth_utils import add_0x_prefix
from multiproof import StandardMerkleTree
from sw_utils.signing import get_v1_withdrawal_credentials

from src.validators.signing.common import encode_tx_validator
from src.validators.typings import DepositData, DepositDataValidator

logger = logging.getLogger(__name__)


def load_deposit_data(vault: HexAddress, deposit_data_file: Path) -> DepositData:
    """Loads and verifies deposit data."""
    with open(deposit_data_file, 'r', encoding='utf-8') as f:
        deposit_data = json.load(f)

    tree, validators = generate_validators_tree(vault, deposit_data)
    return DepositData(validators=validators, tree=tree)


def generate_validators_tree(
    vault: HexAddress, deposit_data: list[dict]
) -> tuple[StandardMerkleTree, list[DepositDataValidator]]:
    """Generates validators tree."""
    credentials = get_v1_withdrawal_credentials(vault)
    leaves: list[tuple[bytes, int]] = []
    validators: list[DepositDataValidator] = []
    for i, data in enumerate(deposit_data):
        validator = DepositDataValidator(
            deposit_data_index=i,
            public_key=add_0x_prefix(data['pubkey']),
            signature=add_0x_prefix(data['signature']),
            amount_gwei=int(data['amount']),
        )
        leaves.append((encode_tx_validator(credentials, validator), i))
        validators.append(validator)

    tree = StandardMerkleTree.of(leaves, ['bytes', 'uint256'])
    return tree, validators
