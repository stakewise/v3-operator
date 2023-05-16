import milagro_bls_binding as bls
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Random.random import randint
from eth_typing import HexStr
from py_ecc.optimized_bls12_381.optimized_curve import curve_order
from sw_utils.signing import get_exit_message_signing_root
from sw_utils.typings import ConsensusFork
from web3 import Web3

from src.common.typings import Oracles
from src.config.settings import NETWORK_CONFIG
from src.validators.typings import BLSPrivkey, ExitSignatureShards


def get_polynomial_points(coefficients: list[int], num_points: int) -> list[bytes]:
    """Calculates polynomial points."""
    points = []
    for x in range(1, num_points + 1):
        # start with x=1 and calculate the value of y
        y = coefficients[0]
        # calculate each term and add it to y, using modular math
        for i in range(1, len(coefficients)):
            exponentiation = (x ** i) % curve_order
            term = (coefficients[i] * exponentiation) % curve_order
            y = (y + term) % curve_order
        # add the point to the list of points
        points.append(y.to_bytes(32, 'big'))
    return points


def encrypt_oracle_data(public_key: RSA.RsaKey, data: bytes) -> bytes:
    """Encrypts data with oracle's public key."""
    session_key = get_random_bytes(32)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)  # type: ignore
    return enc_session_key + cipher_aes.nonce + tag + ciphertext  # type: ignore


def get_exit_signature_shards(
    validator_index: int,
    private_key: BLSPrivkey,
    oracles: Oracles,
    fork: ConsensusFork
) -> ExitSignatureShards:
    """Generates exit signature shards and encrypts them with oracles' RSA keys."""
    message = get_exit_message_signing_root(
        validator_index=validator_index,
        genesis_validators_root=NETWORK_CONFIG.GENESIS_VALIDATORS_ROOT,
        fork=fork
    )

    if len(oracles.rsa_public_keys) == 1:
        rsa_pub_key = oracles.rsa_public_keys[0]
        shard = encrypt_oracle_data(rsa_pub_key, bls.Sign(private_key, message))
        return ExitSignatureShards(
            public_keys=[Web3.to_hex(bls.SkToPk(private_key))],
            exit_signatures=[Web3.to_hex(shard)]
        )

    coefficients: list[int] = [int.from_bytes(private_key, 'big')]
    for _ in range(oracles.threshold - 1):
        coefficients.append(randint(0, curve_order - 1))

    private_keys = get_polynomial_points(coefficients, len(oracles.rsa_public_keys))
    exit_signature_shards: list[HexStr] = []
    for bls_priv_key, rsa_pub_key in zip(private_keys, oracles.rsa_public_keys):
        shard = encrypt_oracle_data(
            public_key=rsa_pub_key,
            data=bls.Sign(bls_priv_key, message)
        )
        exit_signature_shards.append(Web3.to_hex(shard))

    return ExitSignatureShards(
        public_keys=[Web3.to_hex(bls.SkToPk(priv_key)) for priv_key in private_keys],
        exit_signatures=exit_signature_shards
    )
