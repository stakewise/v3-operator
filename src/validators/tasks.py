import asyncio
import logging
import time

from multiproof.standard import MultiProof
from sw_utils import EventScanner, IpfsFetchClient
from sw_utils.typings import Bytes32
from web3 import Web3
from web3.types import BlockNumber, Wei

from src.common.consensus import get_chain_finalized_head
from src.common.contracts import v2_pool_escrow_contract, validators_registry_contract
from src.common.exceptions import NotEnoughOracleApprovalsError
from src.common.execution import check_gas_price, get_oracles
from src.common.metrics import metrics
from src.common.tasks import BaseTask
from src.common.typings import Oracles
from src.common.utils import MGNO_RATE, WAD, get_current_timestamp
from src.config.networks import GNOSIS
from src.config.settings import DEPOSIT_AMOUNT, settings
from src.validators.database import NetworkValidatorCrud
from src.validators.execution import (
    NetworkValidatorsProcessor,
    get_available_validators,
    get_latest_network_validator_public_keys,
    get_withdrawable_assets,
    register_multiple_validator,
    register_single_validator,
    update_unused_validator_keys_metric,
)
from src.validators.keystores.base import BaseKeystore
from src.validators.signing.common import get_validators_proof
from src.validators.typings import (
    ApprovalRequest,
    DepositData,
    NetworkValidator,
    Validator,
)
from src.validators.utils import send_approval_requests

logger = logging.getLogger(__name__)


class ValidatorsTask(BaseTask):
    keystore: BaseKeystore
    deposit_data: DepositData

    def __init__(
        self,
        keystore: BaseKeystore,
        deposit_data: DepositData,
    ):
        self.keystore = keystore
        self.deposit_data = deposit_data
        network_validators_processor = NetworkValidatorsProcessor()
        self.network_validators_scanner = EventScanner(network_validators_processor)

    async def process_block(self) -> None:
        chain_state = await get_chain_finalized_head()

        # process new network validators
        await self.network_validators_scanner.process_new_events(chain_state.execution_block)
        # check and register new validators
        await update_unused_validator_keys_metric(
            keystore=self.keystore,
            deposit_data=self.deposit_data,
        )
        await register_validators(
            keystore=self.keystore,
            deposit_data=self.deposit_data,
        )


# pylint: disable-next=too-many-locals,too-many-branches
async def register_validators(
    keystore: BaseKeystore,
    deposit_data: DepositData,
) -> None:
    """Registers vault validators."""
    if (
        settings.network_config.IS_SUPPORT_V2_MIGRATION
        and settings.is_genesis_vault
        and await v2_pool_escrow_contract.get_owner() != settings.vault
    ):
        logger.info(
            'Waiting for vault to become owner of v2 pool escrow to start registering validators...'
        )
        return

    vault_balance, update_state_call = await get_withdrawable_assets()
    if settings.network == GNOSIS:
        # apply GNO -> mGNO exchange rate
        vault_balance = Wei(int(vault_balance * MGNO_RATE // WAD))

    metrics.stakeable_assets.set(int(vault_balance))

    # calculate number of validators that can be registered
    validators_count = vault_balance // DEPOSIT_AMOUNT
    if not validators_count:
        # not enough balance to register validators
        return

    # get latest oracles
    oracles = await get_oracles()

    validators_count = min(oracles.validators_approval_batch_limit, validators_count)

    if not await check_gas_price():
        return

    validators: list[Validator] = await get_available_validators(
        keystore=keystore,
        deposit_data=deposit_data,
        count=validators_count,
    )
    if not validators:
        logger.warning(
            'There are no available validators in the current deposit data '
            'to proceed with registration. '
            'To register additional validators, you must upload new deposit data.'
        )
        return

    logger.info('Started registration of %d validator(s)', len(validators))

    tx_validators, multi_proof = get_validators_proof(
        tree=deposit_data.tree,
        validators=validators,
    )
    registry_root = None
    oracles_request = None
    deadline = get_current_timestamp() + oracles.signature_validity_period
    approvals_min_interval = 1

    while True:
        approval_start_time = time.time()

        latest_registry_root = await validators_registry_contract.get_registry_root()
        current_timestamp = get_current_timestamp()
        if (
            not registry_root
            or registry_root != latest_registry_root
            or deadline <= current_timestamp
        ):
            registry_root = latest_registry_root
            deadline = current_timestamp + oracles.signature_validity_period
            logger.debug('Fetched latest validators registry root: %s', Web3.to_hex(registry_root))

            oracles_request = await create_approval_request(
                oracles=oracles,
                keystore=keystore,
                validators=validators,
                registry_root=registry_root,
                multi_proof=multi_proof,
                deadline=deadline,
            )

        try:
            oracles_approval = await send_approval_requests(oracles, oracles_request)
            break
        except NotEnoughOracleApprovalsError as e:
            logger.error(
                'Not enough oracle approvals for validator registration: %d. Threshold is %d.',
                e.num_votes,
                e.threshold,
            )
        approvals_time = time.time() - approval_start_time
        await asyncio.sleep(approvals_min_interval - approvals_time)

    # compare validators root just before transaction to reduce reverted calls
    if registry_root != await validators_registry_contract.get_registry_root():
        logger.info(
            'Registry root has changed during validators registration. Retrying...',
        )
        return

    if len(validators) == 1:
        validator = validators[0]
        tx_hash = await register_single_validator(
            approval=oracles_approval,
            multi_proof=multi_proof,
            tx_validators=tx_validators,
            update_state_call=update_state_call,
            validators_registry_root=registry_root,
        )
        if tx_hash:
            logger.info(
                'Successfully registered validator with public key %s', validator.public_key
            )

    if len(validators) > 1:
        tx_hash = await register_multiple_validator(
            approval=oracles_approval,
            multi_proof=multi_proof,
            tx_validators=tx_validators,
            update_state_call=update_state_call,
            validators_registry_root=registry_root,
        )
        if tx_hash:
            pub_keys = ', '.join([val.public_key for val in validators])
            logger.info('Successfully registered validators with public keys %s', pub_keys)


# pylint: disable-next=too-many-arguments
async def create_approval_request(
    oracles: Oracles,
    keystore: BaseKeystore,
    validators: list[Validator],
    registry_root: Bytes32,
    multi_proof: MultiProof,
    deadline: int,
) -> ApprovalRequest:
    """Generate validator registration request data"""

    # get next validator index for exit signature
    latest_public_keys = await get_latest_network_validator_public_keys()
    validator_index = NetworkValidatorCrud().get_next_validator_index(list(latest_public_keys))
    logger.debug('Next validator index for exit signature: %d', validator_index)

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
        proof_indexes=[val[1] for val in multi_proof.leaves],
        deadline=deadline,
    )
    for validator in validators:
        shards = await keystore.get_exit_signature_shards(
            validator_index=validator_index,
            public_key=validator.public_key,
            oracles=oracles,
            fork=settings.network_config.SHAPELLA_FORK,
        )

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


async def load_genesis_validators() -> None:
    """
    Load consensus network validators from the ipfs dump.
    Used to speed up service startup
    """
    ipfs_hash = settings.network_config.GENESIS_VALIDATORS_IPFS_HASH
    if not (NetworkValidatorCrud().get_last_network_validator() is None and ipfs_hash):
        return

    ipfs_fetch_client = IpfsFetchClient(
        ipfs_endpoints=settings.ipfs_fetch_endpoints,
        timeout=settings.genesis_validators_ipfs_timeout,
        retry_timeout=settings.genesis_validators_ipfs_retry_timeout,
    )
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
