import asyncio
import logging
import time
from typing import Sequence, cast

from eth_typing import HexStr
from multiproof.standard import MultiProof
from sw_utils import EventScanner, InterruptHandler, IpfsFetchClient, convert_to_mgno
from sw_utils.typings import Bytes32, ProtocolConfig
from web3 import Web3
from web3.types import BlockNumber

from src.common.checks import wait_execution_catch_up_consensus
from src.common.consensus import get_chain_finalized_head
from src.common.contracts import v2_pool_escrow_contract, validators_registry_contract
from src.common.exceptions import NotEnoughOracleApprovalsError
from src.common.execution import check_gas_price, get_protocol_config
from src.common.harvest import get_harvest_params
from src.common.metrics import metrics
from src.common.tasks import BaseTask
from src.common.typings import HarvestParams
from src.common.utils import get_current_timestamp
from src.config.networks import GNOSIS_NETWORKS
from src.config.settings import DEPOSIT_AMOUNT, settings
from src.validators.database import NetworkValidatorCrud
from src.validators.exceptions import MissingDepositDataValidatorsException
from src.validators.execution import (
    NetworkValidatorsProcessor,
    get_validators_from_deposit_data,
    get_validators_start_index,
    get_withdrawable_assets,
    update_unused_validator_keys_metric,
)
from src.validators.keystores.base import BaseKeystore
from src.validators.register_validators import register_validators
from src.validators.relayer import RelayerAdapter
from src.validators.signing.common import (
    get_encrypted_exit_signature_shards,
    get_validators_proof,
)
from src.validators.typings import (
    ApprovalRequest,
    DepositData,
    NetworkValidator,
    Validator,
    ValidatorsRegistrationMode,
)
from src.validators.utils import send_approval_requests

logger = logging.getLogger(__name__)


class ValidatorsTask(BaseTask):
    def __init__(
        self,
        keystore: BaseKeystore | None,
        deposit_data: DepositData | None,
        relayer_adapter: RelayerAdapter | None,
    ):
        self.keystore = keystore
        self.deposit_data = deposit_data
        network_validators_processor = NetworkValidatorsProcessor()
        self.network_validators_scanner = EventScanner(network_validators_processor)
        self.relayer_adapter = relayer_adapter

    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        chain_state = await get_chain_finalized_head()
        await wait_execution_catch_up_consensus(
            chain_state=chain_state, interrupt_handler=interrupt_handler
        )

        # process new network validators
        await self.network_validators_scanner.process_new_events(chain_state.block_number)

        if self.keystore and self.deposit_data:
            await update_unused_validator_keys_metric(
                keystore=self.keystore,
                deposit_data=self.deposit_data,
            )
        # check and register new validators
        await process_validators(
            keystore=self.keystore,
            deposit_data=self.deposit_data,
            relayer_adapter=self.relayer_adapter,
        )


# pylint: disable-next=too-many-locals,too-many-branches,too-many-return-statements,too-many-statements
async def process_validators(
    keystore: BaseKeystore | None,
    deposit_data: DepositData | None,
    relayer_adapter: RelayerAdapter | None = None,
) -> HexStr | None:
    """
    Calculates vault assets, requests oracles approval, submits registration tx
    """
    if (
        settings.network_config.IS_SUPPORT_V2_MIGRATION
        and settings.is_genesis_vault
        and await v2_pool_escrow_contract.get_owner() != settings.vault
    ):
        logger.info(
            'Waiting for vault to become owner of v2 pool escrow to start registering validators...'
        )
        return None

    harvest_params = await get_harvest_params()
    validators_count = await get_validators_count_from_vault_assets(harvest_params)

    if not validators_count:
        # not enough balance to register validators
        return None

    # Check if there is enough ETH to register the specified minimum number of validators
    if validators_count < settings.min_validators_registration:
        logger.debug(
            'Not enough ETH to register %d validators. Current balance allows for %d validators.',
            settings.min_validators_registration,
            validators_count,
        )
        return None

    # get latest config
    protocol_config = await get_protocol_config()

    validators_batch_size = min(protocol_config.validators_approval_batch_limit, validators_count)
    validators_manager_signature: HexStr | None = None
    validators: Sequence[Validator]
    multi_proof: MultiProof[tuple[bytes, int]] | None

    if settings.validators_registration_mode == ValidatorsRegistrationMode.AUTO:
        validators = await get_validators_from_deposit_data(
            keystore=keystore,
            deposit_data=cast(DepositData, deposit_data),
            count=validators_batch_size,
        )
        if not validators:
            if not settings.disable_deposit_data_warnings:
                logger.warning(
                    'There are no available validators in the current deposit data '
                    'to proceed with registration. '
                    'To register additional validators, you must upload new deposit data.'
                )
            return None
        multi_proof = get_validators_proof(
            tree=cast(DepositData, deposit_data).tree,
            validators=validators,
        )
    else:
        try:
            validators_response = await cast(RelayerAdapter, relayer_adapter).get_validators(
                validators_batch_size, validators_total=validators_count
            )
        except MissingDepositDataValidatorsException:
            # Deposit data validators are required when using DVT Relayer
            if not settings.disable_deposit_data_warnings:
                logger.warning(
                    'There are no available validators in the current deposit data '
                    'to proceed with registration. '
                    'To register additional validators, you must upload new deposit data.'
                )
            return None

        validators = validators_response.validators
        if not validators:
            logger.info('Waiting for relayer validators')
            return None
        validators_manager_signature = validators_response.validators_manager_signature
        multi_proof = validators_response.multi_proof

    if not await check_gas_price(high_priority=True):
        return None

    logger.info('Started registration of %d validator(s)', len(validators))

    registry_root = None
    oracles_request = None
    protocol_config = await get_protocol_config()
    deadline = get_current_timestamp() + protocol_config.signature_validity_period
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
            deadline = current_timestamp + protocol_config.signature_validity_period
            logger.debug('Fetched latest validators registry root: %s', Web3.to_hex(registry_root))

            oracles_request = await create_approval_request(
                protocol_config=protocol_config,
                keystore=keystore,
                validators=validators,
                registry_root=registry_root,
                multi_proof=multi_proof,
                deadline=deadline,
                validators_manager_signature=validators_manager_signature,
            )

        try:
            oracles_approval = await send_approval_requests(protocol_config, oracles_request)
            break
        except NotEnoughOracleApprovalsError as e:
            logger.error(
                'Not enough oracle approvals for validator registration: %d. Threshold is %d.',
                e.num_votes,
                e.threshold,
            )
        approvals_time = time.time() - approval_start_time
        await asyncio.sleep(approvals_min_interval - approvals_time)

    tx_hash = await register_validators(
        approval=oracles_approval,
        multi_proof=multi_proof,
        validators=validators,
        harvest_params=harvest_params,
        validators_registry_root=registry_root,
        validators_manager_signature=validators_manager_signature,
    )
    if tx_hash:
        pub_keys = ', '.join([val.public_key for val in validators])
        logger.info('Successfully registered validator(s) with public key(s) %s', pub_keys)

    return tx_hash


async def get_validators_count_from_vault_assets(harvest_params: HarvestParams | None) -> int:
    vault_balance = await get_withdrawable_assets(harvest_params)
    if settings.network in GNOSIS_NETWORKS:
        # apply GNO -> mGNO exchange rate
        vault_balance = convert_to_mgno(vault_balance)

    metrics.stakeable_assets.set(int(vault_balance))

    # calculate number of validators that can be registered
    validators_count = vault_balance // DEPOSIT_AMOUNT
    return validators_count


# pylint: disable-next=too-many-arguments,too-many-locals
async def create_approval_request(
    protocol_config: ProtocolConfig,
    keystore: BaseKeystore | None,
    validators: Sequence[Validator],
    registry_root: Bytes32,
    multi_proof: MultiProof[tuple[bytes, int]] | None,
    deadline: int,
    validators_manager_signature: HexStr | None,
) -> ApprovalRequest:
    """Generate validator registration request data"""

    # get next validator index for exit signature
    validators_start_index = await get_validators_start_index()
    logger.debug('Next validator index for exit signature: %d', validators_start_index)

    proof, proof_flags, proof_indexes = None, None, None

    if multi_proof:
        proof = multi_proof.proof
        proof_flags = multi_proof.proof_flags
        proof_indexes = [leaf[1] for leaf in multi_proof.leaves]

    # get exit signature shards
    request = ApprovalRequest(
        validator_index=validators_start_index,
        vault_address=settings.vault,
        validators_root=Web3.to_hex(registry_root),
        public_keys=[],
        deposit_signatures=[],
        public_key_shards=[],
        exit_signature_shards=[],
        proof=proof,
        proof_flags=proof_flags,
        proof_indexes=proof_indexes,
        deadline=deadline,
        validators_manager_signature=validators_manager_signature,
    )

    for validator_index, validator in enumerate(validators, validators_start_index):
        shards = validator.exit_signature_shards

        if not shards:
            shards = await get_encrypted_exit_signature_shards(
                keystore=keystore,
                public_key=validator.public_key,
                validator_index=validator_index,
                protocol_config=protocol_config,
                exit_signature=validator.exit_signature,
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
