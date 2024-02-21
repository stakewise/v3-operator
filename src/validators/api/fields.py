from eth_typing import BLSPubkey, BLSSignature
from pydantic import BeforeValidator
from typing_extensions import Annotated

from src.validators.api.validators import to_bls_pubkey, to_bls_signature

BLSPubkeyField = Annotated[BLSPubkey, BeforeValidator(to_bls_pubkey)]
BLSSignatureField = Annotated[BLSSignature, BeforeValidator(to_bls_signature)]
