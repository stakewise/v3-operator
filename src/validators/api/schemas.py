from pydantic import BaseModel

from src.validators.api.fields import BLSPubkeyField, BLSSignatureField


class ValidatorRegistrationRequest(BaseModel):
    public_key: BLSPubkeyField
    exit_signature: BLSSignatureField
