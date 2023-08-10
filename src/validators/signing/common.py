import ecies
from eth_typing import BLSSignature, HexStr
from web3 import Web3


def encrypt_signature(oracle_pubkey: HexStr, signature: BLSSignature) -> HexStr:
    return Web3.to_hex(ecies.encrypt(oracle_pubkey, signature))
