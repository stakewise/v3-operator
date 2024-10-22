from eth_typing import BLSPubkey, BLSSignature
from py_ecc.bls.g2_primitives import (
    G1_to_pubkey,
    G2_to_signature,
    pubkey_to_G1,
    signature_to_G2,
)
from py_ecc.optimized_bls12_381 import Z1, Z2, add, curve_order, multiply
from py_ecc.utils import prime_field_inv


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
