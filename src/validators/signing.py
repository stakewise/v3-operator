import ecies
import milagro_bls_binding as bls
from Cryptodome.Random.random import randint
from eth_typing import HexStr
from multiproof import StandardMerkleTree
from multiproof.standart import MultiProof
from py_ecc.optimized_bls12_381.optimized_curve import curve_order
from sw_utils import get_eth1_withdrawal_credentials
from sw_utils.signing import compute_deposit_data, get_exit_message_signing_root
from sw_utils.typings import ConsensusFork
from web3 import Web3

from src.common.typings import Oracles
from src.config.settings import DEPOSIT_AMOUNT_GWEI, settings
from src.validators.typings import BLSPrivkey, ExitSignatureShards, Validator


def get_polynomial_points(coefficients: list[int], num_points: int) -> list[bytes]:
    """Calculates polynomial points."""
    points = []
    for x in range(1, num_points + 1):
        # start with x=1 and calculate the value of y
        y = coefficients[0]
        # calculate each term and add it to y, using modular math
        for i in range(1, len(coefficients)):
            exponentiation = (x**i) % curve_order
            term = (coefficients[i] * exponentiation) % curve_order
            y = (y + term) % curve_order
        # add the point to the list of points
        points.append(y.to_bytes(32, 'big'))
    return points


def get_exit_signature_shards(
    validator_index: int, private_key: BLSPrivkey, oracles: Oracles, fork: ConsensusFork
) -> ExitSignatureShards:
    """Generates exit signature shards and encrypts them with oracles' public keys."""
    message = get_exit_message_signing_root(
        validator_index=validator_index,
        genesis_validators_root=settings.network_config.GENESIS_VALIDATORS_ROOT,
        fork=fork,
    )

    if len(oracles.public_keys) == 1:
        pub_key = oracles.public_keys[0]
        shard = ecies.encrypt(pub_key, bls.Sign(private_key, message))
        return ExitSignatureShards(
            public_keys=[Web3.to_hex(bls.SkToPk(private_key))], exit_signatures=[Web3.to_hex(shard)]
        )

    coefficients: list[int] = [int.from_bytes(private_key, 'big')]

    for _ in range(oracles.exit_signature_recover_threshold - 1):
        coefficients.append(randint(0, curve_order - 1))

    private_keys = get_polynomial_points(coefficients, len(oracles.public_keys))
    exit_signature_shards: list[HexStr] = []
    for bls_priv_key, pub_key in zip(private_keys, oracles.public_keys):
        shard = ecies.encrypt(pub_key, bls.Sign(bls_priv_key, message))
        exit_signature_shards.append(Web3.to_hex(shard))

    return ExitSignatureShards(
        public_keys=[Web3.to_hex(bls.SkToPk(priv_key)) for priv_key in private_keys],
        exit_signatures=exit_signature_shards,
    )


def get_validators_proof(
    tree: StandardMerkleTree,
    validators: list[Validator],
) -> tuple[list[bytes], MultiProof]:
    credentials = get_eth1_withdrawal_credentials(settings.vault)
    tx_validators: list[bytes] = []
    leaves: list[tuple[bytes, int]] = []
    for validator in validators:
        tx_validator = encode_tx_validator(credentials, validator)
        tx_validators.append(tx_validator)
        leaves.append((tx_validator, validator.deposit_data_index))

    multi_proof = tree.get_multi_proof(leaves)
    return tx_validators, multi_proof


def encode_tx_validator(withdrawal_credentials: bytes, validator: Validator) -> bytes:
    public_key = Web3.to_bytes(hexstr=validator.public_key)
    signature = Web3.to_bytes(hexstr=validator.signature)
    deposit_root = compute_deposit_data(
        public_key=public_key,
        withdrawal_credentials=withdrawal_credentials,
        amount_gwei=DEPOSIT_AMOUNT_GWEI,
        signature=signature,
    ).hash_tree_root
    return public_key + signature + deposit_root
