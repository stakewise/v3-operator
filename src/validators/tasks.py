import logging

from eth_typing import BLSPubkey
from multiproof.standart import MultiProof
from sw_utils.typings import Bytes32
from web3 import Web3
from web3.types import BlockNumber, Wei

from src.common.clients import consensus_client, ipfs_fetch_client
from src.common.contracts import validators_registry_contract
from src.common.execution import check_gas_price, get_oracles
from src.common.metrics import metrics
from src.common.typings import Oracles
from src.common.utils import MGNO_RATE, WAD
from src.config.networks import GNOSIS
from src.config.settings import DEPOSIT_AMOUNT, settings
from src.validators.database import NetworkValidatorCrud
from src.validators.execution import (
    get_available_validators,
    get_latest_network_validator_public_keys,
    get_withdrawable_assets,
    register_multiple_validator,
    register_single_validator,
)
from src.validators.signing.common import get_validators_proof
from src.validators.signing.local import get_exit_signature_shards
from src.validators.signing.remote import (
    RemoteSignerConfiguration,
    get_exit_signature_shards_remote_signer,
)
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


# pylint: disable-next=too-many-locals
async def register_validators(
    keystores: Keystores,
    remote_signer_config: RemoteSignerConfiguration | None,
    deposit_data: DepositData,
) -> None:
    """Registers vault validators."""
    vault_balance, update_state_call = await get_withdrawable_assets()
    if settings.network == GNOSIS:
        # apply GNO -> mGNO exchange rate
        vault_balance = Wei(int(vault_balance * MGNO_RATE // WAD))

    metrics.stakeable_assets.set(int(vault_balance))

    # get latest oracles
    oracles = await get_oracles()
    logger.debug('Fetched latest oracles: %s', oracles)

    approval_max_validators = oracles.validators_approval_batch_limit

    # calculate number of validators that can be registered
    validators_count: int = min(approval_max_validators, vault_balance // DEPOSIT_AMOUNT)
    if not validators_count:
        # not enough balance to register validators
        return

    if not await check_gas_price():
        return

    logger.info('Started registration of %d validator(s)', validators_count)

    validators: list[Validator] = await get_available_validators(
        keystores=keystores,
        remote_signer_config=remote_signer_config,
        deposit_data=deposit_data,
        count=validators_count,
    )
    if not validators:
        logger.warning(
            'There are not enough available validators in the current deposit data '
            'to proceed with registration. '
            'To register additional validators, you must upload new deposit data.'
        )
        return

    tx_validators, multi_proof = get_validators_proof(
        tree=deposit_data.tree,
        validators=validators,
    )
    registry_root = None
    while True:
        latest_registry_root = await validators_registry_contract.get_registry_root()

        if not registry_root or registry_root != latest_registry_root:
            registry_root = latest_registry_root
            logger.debug('Fetched latest validators registry root: %s', registry_root)

            oracles_request = await create_approval_request(
                oracles=oracles,
                keystores=keystores,
                remote_signer_config=remote_signer_config,
                validators=validators,
                registry_root=registry_root,
                multi_proof=multi_proof,
            )

        try:
            oracles_approval = await get_oracles_approval(oracles=oracles, request=oracles_request)
            break
        except Exception as e:
            logger.exception(e)

    if len(validators) == 1:
        validator = validators[0]
        await register_single_validator(
            approval=oracles_approval,
            multi_proof=multi_proof,
            tx_validators=tx_validators,
            update_state_call=update_state_call,
            validators_registry_root=registry_root,
        )
        logger.info('Successfully registered validator with public key %s', validator.public_key)

    if len(validators) > 1:
        await register_multiple_validator(
            approval=oracles_approval,
            multi_proof=multi_proof,
            tx_validators=tx_validators,
            update_state_call=update_state_call,
            validators_registry_root=registry_root,
        )
        pub_keys = ', '.join([val.public_key for val in validators])
        logger.info('Successfully registered validators with public keys %s', pub_keys)


# pylint: disable-next=too-many-arguments
async def create_approval_request(
    oracles: Oracles,
    keystores: Keystores,
    remote_signer_config: RemoteSignerConfiguration | None,
    validators: list[Validator],
    registry_root: Bytes32,
    multi_proof: MultiProof,
) -> ApprovalRequest:
    """Generate validator registration request data"""

    # get next validator index for exit signature
    latest_public_keys = await get_latest_network_validator_public_keys()
    validator_index = NetworkValidatorCrud().get_next_validator_index(list(latest_public_keys))
    logger.debug('Next validator index for exit signature: %d', validator_index)

    # fetch current fork data
    fork = await consensus_client.get_consensus_fork()
    logger.debug('Fetched current fork data: %s', fork)

    # get exit signature shards
    request = ApprovalRequest(
        validator_index=validator_index,
        vault_address=settings.vault,
        validators_root=Web3.to_hex(registry_root),
        public_keys=[],
        deposit_signatures=[],
        public_key_shards=[],
        exit_signature_shards=[],
        proof=multi_proof.proof,
        proof_flags=multi_proof.proof_flags,
    )
    for validator in validators:
        if len(keystores) > 0:
            shards = get_exit_signature_shards(
                validator_index=validator_index,
                private_key=keystores[validator.public_key],
                oracles=oracles,
                fork=fork,
            )
        elif remote_signer_config:
            pubkey_shares = remote_signer_config.pubkeys_to_shares[validator.public_key]
            shards = await get_exit_signature_shards_remote_signer(
                validator_index=validator_index,
                validator_pubkey_shares=[BLSPubkey(Web3.to_bytes(hexstr=s)) for s in pubkey_shares],
                oracles=oracles,
                fork=fork,
            )
        else:
            raise RuntimeError('No keystores and no remote signer URL provided')

        if not shards:
            logger.warning(
                'Failed to get exit signature shards for validator %s', validator.public_key
            )
            break

        request.public_keys.append(validator.public_key)
        request.deposit_signatures.append(validator.signature)
        request.public_key_shards.append(shards.public_keys)
        request.exit_signature_shards.append(shards.exit_signatures)

        validator_index += 1
    return request


async def get_oracles_approval(oracles: Oracles, request: ApprovalRequest) -> OraclesApproval:
    """Fetches approval from oracles."""
    # send approval request to oracles
    signatures, ipfs_hash = await send_approval_requests(oracles, request)
    logger.info(
        'Fetched oracles approval for validators: count=%d, start index=%d',
        len(request.public_keys),
        request.validator_index,
    )
    return OraclesApproval(
        signatures=signatures,
        ipfs_hash=ipfs_hash,
    )


async def load_genesis_validators() -> None:
    """
    Load consensus network validators from the ipfs dump.
    Used to speed up service startup
    """
    ipfs_hash = settings.network_config.GENESIS_VALIDATORS_IPFS_HASH
    if not (NetworkValidatorCrud().get_last_network_validator() is None and ipfs_hash):
        return

    data = await ipfs_fetch_client.fetch_bytes(ipfs_hash)
    genesis_validators: list[NetworkValidator] = []
    logger.info('Loading genesis validators...')
    for i in range(0, len(data), 52):
        genesis_validators.append(
            NetworkValidator(
                public_key=Web3.to_hex(data[i + 4 : i + 52]),
                block_number=BlockNumber(int.from_bytes(data[i : i + 4], 'big')),
            )
        )

    NetworkValidatorCrud().save_network_validators(genesis_validators)
    logger.info('Loaded %d genesis validators', len(genesis_validators))
