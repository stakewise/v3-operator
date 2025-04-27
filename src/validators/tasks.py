import logging
from typing import Sequence, cast

from eth_typing import HexStr
from sw_utils import EventScanner, InterruptHandler, IpfsFetchClient, convert_to_mgno
from sw_utils.networks import GNO_NETWORKS
from sw_utils.typings import Bytes32, ProtocolConfig
from web3 import Web3
from web3.types import BlockNumber, ChecksumAddress

from src.common.checks import wait_execution_catch_up_consensus
from src.common.consensus import get_chain_finalized_head
from src.common.contracts import v2_pool_escrow_contract, validators_registry_contract
from src.common.exceptions import NotEnoughOracleApprovalsError
from src.common.execution import build_gas_manager, get_protocol_config
from src.common.harvest import get_harvest_params
from src.common.metrics import metrics
from src.common.tasks import BaseTask
from src.common.typings import HarvestParams, OraclesApproval
from src.common.utils import RateLimiter, get_current_timestamp
from src.config.settings import DEPOSIT_AMOUNT, settings
from src.validators.database import NetworkValidatorCrud
from src.validators.exceptions import MissingDepositDataValidatorsException
from src.validators.execution import (
    NetworkValidatorsProcessor,
    get_validators_start_index,
    get_withdrawable_assets,
)
from src.validators.keystores.base import BaseKeystore
from src.validators.metrics import update_unused_validator_keys_metric
from src.validators.register_validators import register_validators
from src.validators.relayer import RelayerAdapter
from src.validators.signing.common import get_encrypted_exit_signature_shards
from src.validators.typings import (
    ApprovalRequest,
    NetworkValidator,
    Validator,
    ValidatorsRegistrationMode,
)
from src.validators.utils import get_validators_from_x, send_approval_requests
from src.validators.validators_manager import get_validators_manager_signature

logger = logging.getLogger(__name__)


class ValidatorsTask(BaseTask):
    def __init__(
        self,
        keystore: BaseKeystore | None,
        available_public_keys: list[HexStr] | None,
        relayer_adapter: RelayerAdapter | None,
    ):
        self.keystore = keystore
        self.available_public_keys = available_public_keys
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

        if self.keystore and self.available_public_keys:
            await update_unused_validator_keys_metric(
                keystore=self.keystore, available_public_keys=self.available_public_keys
            )
        # check and register new validators
        for vault_address in settings.vaults:
            await process_validators(
                vault_address=vault_address,
                available_public_keys=self.available_public_keys,
                keystore=self.keystore,
                relayer_adapter=self.relayer_adapter,
            )


# pylint: disable-next=too-many-locals,too-many-return-statements,too-many-branches
async def process_validators(
    vault_address: ChecksumAddress,
    keystore: BaseKeystore | None,
    available_public_keys: list[HexStr] | None,
    relayer_adapter: RelayerAdapter | None = None,
) -> HexStr | None:
    """
    Calculates vault assets, requests oracles approval, submits registration tx
    """
    if (
        settings.network_config.IS_SUPPORT_V2_MIGRATION
        and vault_address == settings.network_config.GENESIS_VAULT_CONTRACT_ADDRESS
        and await v2_pool_escrow_contract.get_owner() != vault_address
    ):
        logger.info(
            'Waiting for vault to become owner of v2 pool escrow to start registering validators...'
        )
        return None

    harvest_params = await get_harvest_params(vault_address)
    validators_count = await get_validators_count_from_vault_assets(
        vault_address=vault_address, harvest_params=harvest_params
    )
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
    validators: Sequence[Validator]

    if settings.validators_registration_mode == ValidatorsRegistrationMode.AUTO:
        validators = await get_validators_from_x(
            keystore=cast(BaseKeystore, keystore),
            available_public_keys=cast(list[HexStr], available_public_keys),
            count=validators_batch_size,
            vault_address=vault_address,
        )

        validators_manager_signature = get_validators_manager_signature(
            vault=vault_address,
            validators_registry_root=await validators_registry_contract.get_registry_root(),
            validators=validators,
        )
        if not validators:
            if not settings.disable_deposit_data_warnings:
                logger.warning(
                    'There are no available validators in the current deposit data '
                    'to proceed with registration. '
                    'To register additional validators, you must upload new deposit data.'
                )
            return None
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
        relayer_validators_manager_signature = validators_response.validators_manager_signature
        if not relayer_validators_manager_signature:
            relayer_validators_manager_signature = get_validators_manager_signature(
                vault=vault_address,
                validators_registry_root=await validators_registry_contract.get_registry_root(),
                validators=validators,
            )
        validators_manager_signature = relayer_validators_manager_signature

    gas_manager = build_gas_manager()
    if not await gas_manager.check_gas_price(high_priority=True):
        return None

    logger.info('Started registration of %d validator(s)', len(validators))

    oracles_request, oracles_approval = await poll_oracles_approval(
        vault_address=vault_address,
        keystore=keystore,
        validators=validators,
        validators_manager_signature=validators_manager_signature,
    )
    validators_registry_root = Bytes32(Web3.to_bytes(hexstr=oracles_request.validators_root))
    tx_hash = await register_validators(
        vault_address=vault_address,
        approval=oracles_approval,
        validators=validators,
        harvest_params=harvest_params,
        validators_registry_root=validators_registry_root,
        validators_manager_signature=validators_manager_signature,
    )
    if tx_hash:
        pub_keys = ', '.join([val.public_key for val in validators])
        logger.info('Successfully registered validator(s) with public key(s) %s', pub_keys)

    return tx_hash


async def poll_oracles_approval(
    vault_address: ChecksumAddress,
    keystore: BaseKeystore | None,
    validators: Sequence[Validator],
    validators_manager_signature: HexStr,
) -> tuple[ApprovalRequest, OraclesApproval]:
    """
    Polls oracles for approval of validator registration
    """
    previous_registry_root: Bytes32 | None = None
    oracles_request: ApprovalRequest | None = None
    protocol_config = await get_protocol_config()
    deadline: int | None = None

    approvals_min_interval = 1
    rate_limiter = RateLimiter(approvals_min_interval)

    while True:
        # Keep min interval between requests
        await rate_limiter.ensure_interval()

        # Create new approvals request or reuse the previous one
        current_registry_root = await validators_registry_contract.get_registry_root()
        logger.debug('Fetched validators registry root: %s', Web3.to_hex(current_registry_root))

        current_timestamp = get_current_timestamp()
        if (
            oracles_request is None
            or previous_registry_root is None
            or previous_registry_root != current_registry_root
            or deadline is None
            or deadline <= current_timestamp
        ):
            deadline = current_timestamp + protocol_config.signature_validity_period

            oracles_request = await create_approval_request(
                vault_address=vault_address,
                protocol_config=protocol_config,
                keystore=keystore,
                validators=validators,
                registry_root=current_registry_root,
                deadline=deadline,
                validators_manager_signature=validators_manager_signature,
            )
        previous_registry_root = current_registry_root

        # Send approval requests
        try:
            oracles_approval = await send_approval_requests(protocol_config, oracles_request)
            return oracles_request, oracles_approval
        except NotEnoughOracleApprovalsError as e:
            logger.error(
                'Not enough oracle approvals for validator registration: %d. Threshold is %d.',
                e.num_votes,
                e.threshold,
            )


async def get_validators_count_from_vault_assets(
    vault_address: ChecksumAddress, harvest_params: HarvestParams | None
) -> int:
    vault_balance = await get_withdrawable_assets(
        vault_address=vault_address, harvest_params=harvest_params
    )
    if settings.network in GNO_NETWORKS:
        # apply GNO -> mGNO exchange rate
        vault_balance = convert_to_mgno(vault_balance)

    metrics.stakeable_assets.labels(network=settings.network).set(int(vault_balance))

    # calculate number of validators that can be registered
    validators_count = vault_balance // DEPOSIT_AMOUNT
    return validators_count


# pylint: disable-next=too-many-arguments,too-many-locals
async def create_approval_request(
    vault_address: ChecksumAddress,
    protocol_config: ProtocolConfig,
    keystore: BaseKeystore | None,
    validators: Sequence[Validator],
    registry_root: Bytes32,
    deadline: int,
    validators_manager_signature: HexStr,
) -> ApprovalRequest:
    """Generate validator registration request data"""

    # get next validator index for exit signature
    validators_start_index = await get_validators_start_index()
    logger.debug('Next validator index for exit signature: %d', validators_start_index)

    # get exit signature shards
    request = ApprovalRequest(
        validator_index=validators_start_index,
        vault_address=vault_address,
        validators_root=Web3.to_hex(registry_root),
        public_keys=[],
        deposit_signatures=[],
        public_key_shards=[],
        exit_signature_shards=[],
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
