from src.common.metrics import metrics
from src.validators.database import NetworkValidatorCrud
from src.validators.execution import check_deposit_data_root
from src.validators.keystores.base import BaseKeystore
from src.validators.typings import DepositData


async def update_unused_validator_keys_metric(
    keystore: BaseKeystore,
    deposit_data: DepositData,
) -> int:
    try:
        await check_deposit_data_root(deposit_data.tree.root)
    except RuntimeError:
        metrics.unused_validator_keys.set(0)
        return 0

    validators: int = 0
    for validator in deposit_data.validators:
        if validator.public_key not in keystore:
            continue

        if NetworkValidatorCrud().is_validator_registered(validator.public_key):
            continue
        validators += 1

    metrics.unused_validator_keys.set(validators)

    return validators
