import logging
from typing import Sequence, cast

from eth_typing import HexStr
from multiproof.standard import MultiProof
from sw_utils import EventScanner, InterruptHandler, IpfsFetchClient, convert_to_mgno
from sw_utils.networks import GNO_NETWORKS
from sw_utils.typings import Bytes32
from web3 import Web3
from web3.types import BlockNumber

from src.common.checks import wait_execution_catch_up_consensus
from src.common.consensus import fetch_registered_validators, get_chain_finalized_head
from src.common.contracts import v2_pool_escrow_contract, vault_contract
from src.common.execution import build_gas_manager, get_protocol_config
from src.common.harvest import get_harvest_params
from src.common.metrics import metrics
from src.common.tasks import BaseTask
from src.common.typings import HarvestParams, Validator, ValidatorType
from src.config.settings import (
    DEPOSIT_AMOUNT,
    MIN_DEPOSIT_AMOUNT,
    PECTRA_DEPOSIT_AMOUNT_GWEI,
    settings,
)
from src.validators.database import NetworkValidatorCrud
from src.validators.exceptions import MissingDepositDataValidatorsException
from src.validators.execution import (
    NetworkValidatorsProcessor,
    get_validators_from_deposit_data,
    get_withdrawable_assets,
)
from src.validators.keystores.base import BaseKeystore
from src.validators.metrics import update_unused_validator_keys_metric
from src.validators.oracles import poll_validation_approval
from src.validators.register_validators import fund_validators, register_validators
from src.validators.relayer import RelayerAdapter
from src.validators.signing.common import get_validators_proof
from src.validators.typings import (
    DepositData,
    DepositDataValidator,
    NetworkValidator,
    ValidatorsRegistrationMode,
)

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


# pylint: disable-next=too-many-locals,too-many-return-statements
async def process_validators(
    keystore: BaseKeystore | None,
    deposit_data: DepositData | None,
    relayer_adapter: RelayerAdapter | None = None,
) -> None:
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

    vault_assets = await get_vault_assets(harvest_params)
    if vault_assets < MIN_DEPOSIT_AMOUNT:
        return None

    vault_version = await vault_contract.version()
    if vault_version >= 5:
        vault_validators = await fetch_registered_validators()

        v2_validators_capacity = sum(
            max(PECTRA_DEPOSIT_AMOUNT_GWEI - val.balance, 0)
            for val in vault_validators
            if val.validator_type == ValidatorType.TWO
        )
        if v2_validators_capacity > vault_assets:
            await fund_v2_validators(
                vault_validators,
                amount_gwei=int(Web3.from_wei(vault_assets, 'gwei')),
                harvest_params=harvest_params,
            )
        logger.info('Not enough capacity to fund v2 validators, registering new validators...')

    await register_new_validators(
        vault_assets=vault_assets,
        harvest_params=harvest_params,
        keystore=keystore,
        deposit_data=deposit_data,
        relayer_adapter=relayer_adapter,
    )


async def fund_v2_validators(
    vault_validators: list[Validator], amount_gwei: int, harvest_params: HarvestParams | None
) -> HexStr | None:
    topup_data = _get_topup_data(vault_validators, amount_gwei)
    if not topup_data:
        return None

    logger.info('Started fund of %d validator(s)', len(topup_data))

    validators_data = ...
    validators_manager_signature = ...
    tx_hash = await fund_validators(
        harvest_params=harvest_params,
        validators=validators_data,
        validators_manager_signature=validators_manager_signature,
    )
    if tx_hash:
        pub_keys = ', '.join(topup_data)
        logger.info('Successfully funded validator(s) with public key(s) %s', pub_keys)

    return tx_hash


# pylint: disable-next=too-many-locals,too-many-return-statements,too-many-branches
async def register_new_validators(
    vault_assets: int,
    harvest_params: HarvestParams | None,
    keystore: BaseKeystore | None,
    deposit_data: DepositData | None,
    relayer_adapter: RelayerAdapter | None = None,
) -> HexStr | None:
    # calculate number of validators that can be registered
    if settings.validator_type == ValidatorType.TWO:
        validators_count = vault_assets // PECTRA_DEPOSIT_AMOUNT_GWEI
    else:
        validators_count = vault_assets // DEPOSIT_AMOUNT

    if not validators_count:
        # not enough balance to register validators
        return None

    # Check if there is enough ETH to register the specified minimum number of validators
    if (
        settings.validator_type == ValidatorType.ONE
        and validators_count < settings.min_validators_registration
    ):
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
    validators: Sequence[DepositDataValidator]
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
            logger.debug('Waiting for relayer validators')
            return None
        validators_manager_signature = validators_response.validators_manager_signature
        multi_proof = validators_response.multi_proof

    gas_manager = build_gas_manager()
    if not await gas_manager.check_gas_price(high_priority=True):
        return None

    logger.info('Started registration of %d validator(s)', len(validators))

    oracles_request, oracles_approval = await poll_validation_approval(
        keystore=keystore,
        validators=validators,
        multi_proof=multi_proof,
        validators_manager_signature=validators_manager_signature,
    )
    validators_registry_root = Bytes32(Web3.to_bytes(hexstr=oracles_request.validators_root))

    tx_hash = await register_validators(
        approval=oracles_approval,
        multi_proof=multi_proof,
        validators=validators,
        harvest_params=harvest_params,
        validators_registry_root=validators_registry_root,
        validators_manager_signature=validators_manager_signature,
    )
    if tx_hash:
        pub_keys = ', '.join([val.public_key for val in validators])
        logger.info('Successfully registered validator(s) with public key(s) %s', pub_keys)

    return tx_hash


#
#
# async def get_validators_count_from_vault_assets(harvest_params: HarvestParams | None) -> int:
#     vault_balance = await get_withdrawable_assets(harvest_params)
#     if settings.network in GNO_NETWORKS:
#         # apply GNO -> mGNO exchange rate
#         vault_balance = convert_to_mgno(vault_balance)
#
#     metrics.stakeable_assets.labels(network=settings.network).set(int(vault_balance))
#
#     # calculate number of validators that can be registered
#     validators_count = vault_balance // DEPOSIT_AMOUNT
#     return validators_count


async def get_vault_assets(harvest_params: HarvestParams | None) -> int:
    vault_assets = await get_withdrawable_assets(harvest_params)
    if settings.network in GNO_NETWORKS:
        # apply GNO -> mGNO exchange rate
        vault_assets = convert_to_mgno(vault_assets)

    metrics.stakeable_assets.labels(network=settings.network).set(int(vault_assets))

    return vault_assets


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


def _get_topup_data(vault_validators: list[Validator], amount_gwei: int) -> dict[HexStr, int]:
    v2_validators_capacity = sum(
        max(PECTRA_DEPOSIT_AMOUNT_GWEI - val.balance, 0)
        for val in vault_validators
        if val.validator_type == ValidatorType.TWO
    )
    if v2_validators_capacity < amount_gwei:
        return {}

    vault_validators.sort(key=lambda x: x.balance, reverse=True)
    result = {}
    for validator in vault_validators:
        if PECTRA_DEPOSIT_AMOUNT_GWEI - validator.balance > 0:
            val_amount = min(PECTRA_DEPOSIT_AMOUNT_GWEI - validator.balance, amount_gwei)
            result[validator.public_key] = val_amount
            amount_gwei -= val_amount
        if amount_gwei <= 0:
            break
    return result
