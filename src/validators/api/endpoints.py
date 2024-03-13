import asyncio
import json
from typing import Any

from pydantic import TypeAdapter, ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.status import HTTP_400_BAD_REQUEST
from sw_utils import is_valid_exit_signature
from web3 import Web3

from src.config.settings import settings
from src.validators.api.schemas import ValidatorRegistrationRequest
from src.validators.database import NetworkValidatorCrud
from src.validators.execution import get_latest_network_validator_public_keys
from src.validators.tasks import (
    get_available_validators_for_registration,
    pending_validator_registrations,
    register_and_remove_pending_validators,
)
from src.validators.typings import Validator, ValidatorsRegistrationMode


async def get_validators(request: Request) -> Response:
    deposit_data = request.app.state.deposit_data

    validators = await get_available_validators_for_registration(
        keystore=None, deposit_data=deposit_data, run_check_deposit_data_root=False
    )
    validators = [v for v in validators if v.public_key not in pending_validator_registrations]

    if not validators:
        return JSONResponse([])

    # get next validator index for exit signature
    latest_public_keys = await get_latest_network_validator_public_keys()
    next_validator_index = NetworkValidatorCrud().get_next_validator_index(list(latest_public_keys))

    return JSONResponse(
        [
            {'public_key': validator.public_key, 'index': index}
            for index, validator in enumerate(validators, next_validator_index)
        ]
    )


async def submit_validators(request: Request) -> Response:
    if settings.validators_registration_mode != ValidatorsRegistrationMode.API:
        return JSONResponse(
            {'error': 'validators registration mode must be "API"'},
            status_code=HTTP_400_BAD_REQUEST,
        )

    try:
        payload = await request.json()
    except json.JSONDecodeError:
        return JSONResponse({'error': 'invalid json'}, status_code=HTTP_400_BAD_REQUEST)

    adapter = TypeAdapter(list[ValidatorRegistrationRequest])
    try:
        registration_requests: list[ValidatorRegistrationRequest] = adapter.validate_python(payload)
    except ValidationError as e:
        return JSONResponse({'error': json.loads(e.json())}, status_code=HTTP_400_BAD_REQUEST)

    if not registration_requests:
        return JSONResponse({'error': 'invalid validators'}, status_code=HTTP_400_BAD_REQUEST)

    deposit_data = request.app.state.deposit_data

    validators = await get_available_validators_for_registration(
        keystore=None, deposit_data=deposit_data
    )

    # There may be lag between GET and POST requests.
    # During this time new assets may be staked into the vault.
    # In this case validators list will be longer than requests list.
    #
    # If someone unstakes funds then validators list may become shorter
    # than requests list
    #
    common_length = min(len(validators), len(registration_requests))
    registration_requests = registration_requests[:common_length]

    error = await _validate_registration_requests(registration_requests, validators)
    if error is not None:
        return JSONResponse({'error': error}, status_code=HTTP_400_BAD_REQUEST)

    for validator, registration_request in zip(validators, registration_requests):
        validator.exit_signature = registration_request.exit_signature

    pending_validator_registrations.extend([v.public_key for v in validators])
    asyncio.create_task(
        register_and_remove_pending_validators(
            keystore=None, deposit_data=deposit_data, validators=validators
        )
    )

    return JSONResponse({})


async def _validate_registration_requests(
    registration_requests: list[ValidatorRegistrationRequest], validators: list[Validator]
) -> Any:
    """
    Business logic validation
    :return: error
    """
    if len(validators) < len(registration_requests):
        return 'invalid validators length'

    # get next validator index for exit signature
    latest_public_keys = await get_latest_network_validator_public_keys()
    next_validator_index = NetworkValidatorCrud().get_next_validator_index(list(latest_public_keys))

    # validate public keys and exit signatures
    for registration_request, (validator_index, validator) in zip(
        registration_requests, enumerate(validators, next_validator_index)
    ):
        if validator.public_key != Web3.to_hex(registration_request.public_key):
            return 'invalid validators public_key'

        if not is_valid_exit_signature(
            validator_index,
            registration_request.public_key,
            registration_request.exit_signature,
            settings.network_config.GENESIS_VALIDATORS_ROOT,
            settings.network_config.SHAPELLA_FORK,
        ):
            return 'invalid validators exit_signature'

    return None
