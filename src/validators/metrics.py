from src.common.metrics import metrics
from src.config.settings import settings
from src.validators.database import NetworkValidatorCrud
from src.validators.keystores.base import BaseKeystore


async def update_unused_validator_keys_metric(
    keystore: BaseKeystore,
) -> int:
    validators: int = 0
    for public_key in keystore.public_keys:
        if NetworkValidatorCrud().is_validator_registered(public_key):
            continue
        validators += 1

    metrics.unused_validator_keys.labels(network=settings.network).set(validators)

    return validators
