from src.config.settings import settings
from src.validators.execution import get_validators_from_deposit_data
from src.validators.keystores.local import LocalKeystore
from src.validators.relayer import BaseRelayer
from src.validators.typings import DepositData, RelayerValidator
from src.validators.utils import load_deposit_data


class LocalRelayer(BaseRelayer):
    def __init__(self, keystore: LocalKeystore, deposit_data: DepositData):
        super().__init__()
        self._keystore = keystore
        self._deposit_data = deposit_data

    async def get_validators(self, start_index: int, count: int) -> list[RelayerValidator]:
        deposit_data_validators = await get_validators_from_deposit_data(
            keystore=self._keystore,
            deposit_data=self._deposit_data,
            count=count,
        )
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
        return relayer_validators


async def create_local_relayer() -> LocalRelayer:
    keystore = await LocalKeystore.load()
    deposit_data = load_deposit_data(settings.vault, settings.deposit_data_file)
    return LocalRelayer(keystore, deposit_data)
