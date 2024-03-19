import secrets
from typing import TypeAlias

from eth_typing import BLSPubkey, BLSSignature
from py_ecc.bls import G2ProofOfPossession
from py_ecc.bls.g2_primitives import (
    G1_to_pubkey,
    G2_to_signature,
    pubkey_to_G1,
    signature_to_G2,
)
from py_ecc.bls.hash_to_curve import hash_to_G2
from py_ecc.optimized_bls12_381.optimized_curve import (
    G1 as P1,  # don't confuse group name (G1) with primitive element name (P1)
)
from py_ecc.optimized_bls12_381.optimized_curve import (
    Z1,
    Z2,
    add,
    curve_order,
    multiply,
)
from py_ecc.typing import Optimized_Field, Optimized_Point3D
from py_ecc.utils import prime_field_inv

from src.validators.typings import BLSPrivkey

# element of G1 or G2
G12: TypeAlias = Optimized_Point3D[Optimized_Field]


def get_polynomial_points(coefficients: list[int], num_points: int) -> list[int]:
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
        points.append(y)
    return points


def get_G12_polynomial_points(coefficients: list, num_points: int) -> list:
    """Calculates polynomial points in G1 or G2."""
    points = []
    for x in range(1, num_points + 1):
        # start with x=1 and calculate the value of y
        y = coefficients[0]
        # calculate each term and add it to y, using modular math
        for i in range(1, len(coefficients)):
            exponentiation = (x**i) % curve_order
            term = multiply(coefficients[i], exponentiation)
            y = add(y, term)

        # add the point to the list of points
        points.append(y)
    return points


def private_key_to_private_key_shares(
    private_key: BLSPrivkey,
    threshold: int,
    total: int,
) -> list[BLSPrivkey]:
    coefficients: list[int] = [int.from_bytes(private_key, 'big')]

    for _ in range(threshold - 1):
        coefficients.append(secrets.randbelow(curve_order))

    points = get_polynomial_points(coefficients, total)

    return [BLSPrivkey(p.to_bytes(32, 'big')) for p in points]


def bls_signature_to_shares(
    bls_signature: BLSSignature,
    coefficients_G2: list[G12],
    total: int,
) -> list[BLSSignature]:
    coefficients_G2 = [signature_to_G2(bls_signature)] + coefficients_G2

    points = get_G12_polynomial_points(coefficients_G2, total)

    return [BLSSignature(G2_to_signature(p)) for p in points]


def bls_public_key_to_shares(
    public_key: BLSPubkey,
    coefficients_G1: list,
    total: int,
) -> list[BLSPubkey]:
    coefficients_G1 = [pubkey_to_G1(public_key)] + coefficients_G1

    points = get_G12_polynomial_points(coefficients_G1, total)

    return [BLSPubkey(G1_to_pubkey(p)) for p in points]


def bls_signature_and_public_key_to_shares(
    message: bytes, signature: BLSSignature, public_key: BLSPubkey, threshold: int, total: int
) -> tuple[list[BLSSignature], list[BLSPubkey]]:
    """
    Given `message`, `signature` and `public_key` so that
    `signature` for `message` can be verified with `public_key`.

    The function splits `signature` and `public_key` to shares so that
    each signature share can be verified with corresponding public key share.
    """
    message_g2 = hash_to_G2(message, G2ProofOfPossession.DST, G2ProofOfPossession.xmd_hash_function)

    coefficients_int = [secrets.randbelow(curve_order) for _ in range(threshold - 1)]
    coefficients_G1 = [multiply(P1, coef) for coef in coefficients_int]
    coefficients_G2 = [multiply(message_g2, coef) for coef in coefficients_int]

    bls_signature_shards = bls_signature_to_shares(signature, coefficients_G2, total)
    public_key_shards = bls_public_key_to_shares(public_key, coefficients_G1, total)

    return bls_signature_shards, public_key_shards


def reconstruct_shared_bls_signature(signatures: dict[int, BLSSignature]) -> BLSSignature:
    """
    Reconstructs shared BLS private key signature.
    Copied from https://github.com/dankrad/python-ibft/blob/master/bls_threshold.py
    """
    r = Z2
    for i, sig in signatures.items():
        sig_point = signature_to_G2(sig)
        coef = 1
        for j in signatures:
            if j != i:
                coef = -coef * (j + 1) * prime_field_inv(i - j, curve_order) % curve_order
        r = add(r, multiply(sig_point, coef))
    return G2_to_signature(r)


def get_aggregate_key(keyshares: dict[int, BLSPubkey]) -> BLSPubkey:
    r = Z1
    for i, key in keyshares.items():
        key_point = pubkey_to_G1(key)
        coef = 1
        for j in keyshares:
            if j != i:
                coef = -coef * (j + 1) * prime_field_inv(i - j, curve_order) % curve_order
        r = add(r, multiply(key_point, coef))
    return G1_to_pubkey(r)
