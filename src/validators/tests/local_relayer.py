from src.config.settings import settings
from src.validators.database import NetworkValidatorCrud
from src.validators.keystores.local import LocalKeystore
from src.validators.relayer import BaseRelayerClient
from src.validators.signing.validators_manager import get_validators_manager_signature
from src.validators.typings import (
    DepositData,
    DepositDataValidator,
    RelayerValidator,
    RelayerValidatorsResponse,
)
from src.validators.utils import load_deposit_data


class LocalRelayerClient(BaseRelayerClient):
    def __init__(self, keystore: LocalKeystore, deposit_data: DepositData):
        super().__init__()
        self._keystore = keystore
        self._deposit_data = deposit_data

    async def get_validators(self, start_index: int, count: int) -> RelayerValidatorsResponse:
        deposit_data_validators: list[DepositDataValidator] = []

        for dv in self._deposit_data.validators:
            if len(deposit_data_validators) == count:
                break
            if not NetworkValidatorCrud().is_validator_registered(dv.public_key):
                deposit_data_validators.append(dv)

        fork = settings.network_config.SHAPELLA_FORK

        relayer_validators = []
        validator_indexes = range(start_index, start_index + count)
        for validator_index, validator in zip(validator_indexes, deposit_data_validators):
            exit_signature = await self._keystore.get_exit_signature(
                validator_index=validator_index,
                public_key=validator.public_key,
                fork=fork,
            )
            relayer_validators.append(
                RelayerValidator(
                    public_key=validator.public_key,
                    signature=validator.signature,
                    amount_gwei=validator.amount_gwei,
                    exit_signature=exit_signature,
                )
            )

        validators_manager_signature = await get_validators_manager_signature(
            deposit_data_validators
        )
        return RelayerValidatorsResponse(
            validators=relayer_validators,
            validators_manager_signature=validators_manager_signature,
        )


async def create_local_relayer() -> LocalRelayerClient:
    keystore = await LocalKeystore.load()
    deposit_data = load_deposit_data(settings.vault, settings.deposit_data_file)
    return LocalRelayerClient(keystore, deposit_data)
