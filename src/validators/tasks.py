import logging

from web3 import Web3
from web3.types import Wei

from src.common.clients import ipfs_fetch_client
from src.common.utils import MGNO_RATE, WAD
from src.config.networks import GNOSIS, GOERLI
from src.config.settings import (
    APPROVAL_MAX_VALIDATORS,
    DEPOSIT_AMOUNT,
    GOERLI_GENESIS_VALIDATORS_IPFS_HASH,
    MAX_FEE_PER_GAS_GWEI,
    NETWORK,
    NETWORK_CONFIG,
    VAULT_CONTRACT_ADDRESS,
)
from src.validators.consensus import get_consensus_fork
from src.validators.database import (
    get_last_network_validator,
    get_next_validator_index,
    save_network_validators,
)
from src.validators.execution import (
    check_operator_balance,
    get_available_validators,
    get_latest_network_validator_public_keys,
    get_max_fee_per_gas,
    get_oracles,
    get_validators_registry_root,
    get_withdrawable_assets,
    register_multiple_validator,
    register_single_validator,
)
from src.validators.signing import get_exit_signature_shards
from src.validators.typings import (
    ApprovalRequest,
    DepositData,
    Keystores,
    NetworkValidator,
    OraclesApproval,
    Validator,
)
from src.validators.utils import send_approval_requests

logger = logging.getLogger(__name__)


async def register_validators(keystores: Keystores, deposit_data: DepositData) -> None:
    """Registers vault validators."""
    vault_balance = await get_withdrawable_assets()
    if NETWORK == GNOSIS:
        # apply GNO -> mGNO exchange rate
        vault_balance = Wei(int(vault_balance * MGNO_RATE // WAD))

    # calculate number of validators that can be registered
    validators_count: int = min(APPROVAL_MAX_VALIDATORS, vault_balance // DEPOSIT_AMOUNT)
    if not validators_count:
        # not enough balance to register validators
        return

    max_fee_per_gas = await get_max_fee_per_gas()
    if max_fee_per_gas >= Web3.to_wei(MAX_FEE_PER_GAS_GWEI, 'gwei'):
        logging.warning('Current gas price (%s gwei) is too high. '
                        'Will try to register validator on the next block if the gas '
                        'price is acceptable.', Web3.from_wei(max_fee_per_gas, 'gwei'))
        return

    logger.info('Started registration of %d validators', validators_count)

    validators: list[Validator] = await get_available_validators(
        keystores, deposit_data, validators_count
    )
    if not validators:
        logger.warning('There are not enough available validators in the current deposit data '
                       'to proceed with registration. '
                       'To register additional validators, you must upload new deposit data.')
        return

    oracles_approval = await get_oracles_approval(keystores, validators)

    if len(validators) == 1:
        validator = validators[0]
        await register_single_validator(deposit_data.tree, validator, oracles_approval)
        logger.info('Successfully registered validator with public key %s', validator.public_key)

    if len(validators) > 1:
        await register_multiple_validator(deposit_data.tree, validators, oracles_approval)
        pub_keys = ', '.join([val.public_key for val in validators])
        logger.info('Successfully registered validators with public keys %s', pub_keys)

    # check balance after transaction
    await check_operator_balance()


async def get_oracles_approval(
    keystores: Keystores, validators: list[Validator]
) -> OraclesApproval:
    """Fetches approval from oracles."""
    # get latest oracles
    oracles = await get_oracles()

    # get latest registry root
    registry_root = await get_validators_registry_root()

    # get next validator index for exit signature
    latest_public_keys = await get_latest_network_validator_public_keys()
    validator_index = get_next_validator_index(list(latest_public_keys))
    start_validator_index = validator_index

    # fetch current fork data
    fork = await get_consensus_fork()

    # get exit signature shards
    request = ApprovalRequest(
        validator_index=validator_index,
        vault_address=VAULT_CONTRACT_ADDRESS,
        validators_root=Web3.to_hex(registry_root),
        public_keys=[],
        deposit_signatures=[],
        public_key_shards=[],
        exit_signature_shards=[],
    )
    for validator in validators:
        shards = get_exit_signature_shards(
            validator_index=validator_index,
            private_key=keystores[validator.public_key],
            oracles=oracles,
            fork=fork,
        )
        if not shards:
            break

        request.public_keys.append(validator.public_key)
        request.deposit_signatures.append(validator.signature)
        request.public_key_shards.append(shards.public_keys)
        request.exit_signature_shards.append(shards.exit_signatures)

        validator_index += 1

    # send approval request to oracles
    signatures, ipfs_hash = await send_approval_requests(oracles, request)
    logger.info(
        'Fetched oracles approval for validators: count=%d, start index=%d',
        len(validators),
        start_validator_index,
    )
    return OraclesApproval(
        signatures=signatures,
        ipfs_hash=ipfs_hash,
        validators_registry_root=registry_root,
    )


async def load_genesis_validators() -> None:
    """
    In some test networks (e.g. Goerli) genesis validators
    are not registered through the registry contract.
    """
    if NETWORK != GOERLI or get_last_network_validator() is not None:
        return

    pub_keys = await ipfs_fetch_client.fetch_bytes(GOERLI_GENESIS_VALIDATORS_IPFS_HASH)
    genesis_validators: list[NetworkValidator] = []
    for i in range(0, len(pub_keys), 48):
        genesis_validators.append(
            NetworkValidator(
                public_key=Web3.to_hex(pub_keys[i : i + 48]),
                block_number=NETWORK_CONFIG.VALIDATORS_REGISTRY_GENESIS_BLOCK,
            )
        )

    save_network_validators(genesis_validators)
    logger.info('Loaded %d Goerli genesis validators', len(genesis_validators))
