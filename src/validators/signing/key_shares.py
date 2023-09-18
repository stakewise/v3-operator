from random import randint

from eth_typing import BLSPubkey, BLSSignature
from py_ecc.bls.g2_primitives import (
    G1_to_pubkey,
    G2_to_signature,
    pubkey_to_G1,
    signature_to_G2,
)
from py_ecc.optimized_bls12_381.optimized_curve import (
    Z1,
    Z2,
    add,
    curve_order,
    multiply,
)
from py_ecc.utils import prime_field_inv

from src.validators.typings import BLSPrivkey


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


def private_key_to_private_key_shares(
    private_key: BLSPrivkey,
    threshold: int,
    total: int,
) -> list[BLSPrivkey]:
    coefficients: list[int] = [int.from_bytes(private_key, 'big')]

    for _ in range(threshold - 1):
        coefficients.append(randint(0, curve_order - 1))  # nosec

    points = get_polynomial_points(coefficients, total)

    return [BLSPrivkey(p.to_bytes(32, 'big')) for p in points]


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
