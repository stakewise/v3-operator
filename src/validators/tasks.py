import logging
from typing import Sequence, cast

from eth_typing import HexStr
from sw_utils import InterruptHandler, IpfsFetchClient, convert_to_mgno
from sw_utils.networks import GNO_NETWORKS
from sw_utils.pectra import get_pectra_vault_version
from sw_utils.typings import Bytes32
from web3 import Web3
from web3.types import BlockNumber, ChecksumAddress, Gwei

from src.common.checks import wait_execution_catch_up_consensus
from src.common.consensus import get_chain_finalized_head
from src.common.contracts import (
    VaultContract,
    v2_pool_escrow_contract,
    validators_registry_contract,
)
from src.common.execution import build_gas_manager, get_protocol_config
from src.common.harvest import get_harvest_params
from src.common.metrics import metrics
from src.common.tasks import BaseTask
from src.common.typings import HarvestParams, ValidatorType
from src.config.settings import (
    MAX_EFFECTIVE_BALANCE,
    MAX_EFFECTIVE_BALANCE_GWEI,
    MIN_ACTIVATION_BALANCE,
    MIN_ACTIVATION_BALANCE_GWEI,
    PUBLIC_KEYS_FILENAME,
    settings,
)
from src.validators.consensus import fetch_compounding_validators_balances
from src.validators.database import NetworkValidatorCrud
from src.validators.exceptions import (
    EmptyRelayerResponseException,
    MissingAvailableValidatorsException,
)
from src.validators.execution import get_withdrawable_assets, scan_validators_events
from src.validators.keystores.base import BaseKeystore
from src.validators.metrics import update_unused_validator_keys_metric
from src.validators.oracles import poll_validation_approval
from src.validators.register_validators import fund_validators, register_validators
from src.validators.relayer import RelayerAdapter
from src.validators.typings import (
    NetworkValidator,
    Validator,
    ValidatorsRegistrationMode,
)
from src.validators.utils import get_funded_validators, get_registered_validators
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
        self.relayer_adapter = relayer_adapter

    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        chain_state = await get_chain_finalized_head()
        await wait_execution_catch_up_consensus(
            chain_state=chain_state, interrupt_handler=interrupt_handler
        )

        # process new network validators
        await scan_validators_events(block_number=chain_state.block_number, is_startup=False)

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
) -> None:
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

    vault_assets = await get_vault_assets(
        vault_address=vault_address, harvest_params=harvest_params
    )

    if vault_assets < Web3.to_wei(settings.min_deposit_amount, 'gwei'):
        return None
    vault_contract = VaultContract(vault_address)
    vault_version = await vault_contract.version()
    if vault_version >= get_pectra_vault_version(settings.network, vault_address):
        validators_balances = await fetch_compounding_validators_balances(vault_address)
        try:
            vault_assets = await fund_compounding_validators(
                vault_address=vault_address,
                validators_balances=validators_balances,
                keystore=keystore,
                amount=Gwei(int(Web3.from_wei(vault_assets, 'gwei'))),
                harvest_params=harvest_params,
            )
        except EmptyRelayerResponseException:
            return
        if not vault_assets:
            return
        logger.info(
            'Not enough capacity to fund compounding validators, '
            'trying to register new validators...'
        )

    await register_new_validators(
        vault_address=vault_address,
        vault_assets=vault_assets,
        harvest_params=harvest_params,
        keystore=keystore,
        available_public_keys=available_public_keys,
        relayer_adapter=relayer_adapter,
    )


# pylint: disable-next=too-many-arguments
async def fund_compounding_validators(
    vault_address: ChecksumAddress,
    keystore: BaseKeystore | None,
    validators_balances: dict[HexStr, Gwei],
    amount: Gwei,
    harvest_params: HarvestParams | None,
    relayer_adapter: RelayerAdapter | None = None,
) -> Gwei:
    """
    Funds vault compounding validators with the specified amount.
    Returns the remaining amount after funding.
    """
    funding_amounts = _get_funding_amounts(validators_balances, amount)
    if not funding_amounts:
        raise ValueError('Can not fund validators')

    logger.info('Started funding of %d validator(s)', len(funding_amounts))
    validators_manager_signature = HexStr('0x')
    if settings.validators_registration_mode == ValidatorsRegistrationMode.AUTO:
        validators = await get_funded_validators(
            funding_amounts=funding_amounts,
            keystore=cast(BaseKeystore, keystore),
            vault_address=vault_address,
        )
    else:
        # fetch validators and signature from relayer
        validators_response = await cast(RelayerAdapter, relayer_adapter).fund_validators(
            funding_amounts=funding_amounts,
        )

        validators = validators_response.validators
        if not validators:
            logger.debug('Waiting for relayer validators')
            raise EmptyRelayerResponseException()
        if validators_response.validators_manager_signature:
            validators_manager_signature = validators_response.validators_manager_signature

    tx_hash = await fund_validators(
        vault_address=vault_address,
        harvest_params=harvest_params,
        validators=validators,
        validators_manager_signature=validators_manager_signature,
    )
    if tx_hash:
        pub_keys = ', '.join(funding_amounts.keys())
        logger.info('Successfully funded validator(s) with public key(s) %s', pub_keys)

    left_amount = max(amount - sum(funding_amounts.values()), 0)
    return Gwei(left_amount)


# pylint: disable-next=too-many-locals,too-many-return-statements,too-many-branches,disable-next=too-many-arguments
async def register_new_validators(
    vault_address: ChecksumAddress,
    vault_assets: int,
    harvest_params: HarvestParams | None,
    keystore: BaseKeystore | None,
    available_public_keys: list[HexStr] | None,
    relayer_adapter: RelayerAdapter | None = None,
) -> HexStr | None:
    validators_amounts = _get_deposits_amounts(vault_assets, settings.validator_type)
    validators_count = len(validators_amounts)
    if not validators_amounts:
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
        validators = await get_registered_validators(
            keystore=cast(BaseKeystore, keystore),
            available_public_keys=cast(list[HexStr], available_public_keys),
            amounts=validators_amounts[:validators_batch_size],
            vault_address=vault_address,
        )
        validators_manager_signature = get_validators_manager_signature(
            vault=vault_address,
            validators_registry_root=await validators_registry_contract.get_registry_root(),
            validators=validators,
        )
        if not validators:
            if not settings.disable_available_validators_warnings:
                logger.warning(
                    'There are no available public keys '
                    'in the current %s file '
                    'to proceed with registration. '
                    'To register additional validators, you must generate new keys.',
                    PUBLIC_KEYS_FILENAME,
                )
            return None
    else:
        try:
            validators_response = await cast(RelayerAdapter, relayer_adapter).get_validators(
                validators_batch_size, validators_total=validators_count
            )
        except MissingAvailableValidatorsException:
            if not settings.disable_available_validators_warnings:
                logger.warning(
                    'There are no available public keys '
                    'in the current %s file '
                    'to proceed with registration. '
                    'To register additional validators, you must generate new keys.',
                    PUBLIC_KEYS_FILENAME,
                )
            return None

        validators = validators_response.validators
        if not validators:
            logger.debug('Waiting for relayer validators')
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

    oracles_request, oracles_approval = await poll_validation_approval(
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


async def get_vault_assets(
    vault_address: ChecksumAddress, harvest_params: HarvestParams | None
) -> int:
    vault_balance = await get_withdrawable_assets(
        vault_address=vault_address, harvest_params=harvest_params
    )
    if settings.network in GNO_NETWORKS:
        # apply GNO -> mGNO exchange rate
        vault_balance = convert_to_mgno(vault_balance)

    metrics.stakeable_assets.labels(network=settings.network).set(int(vault_balance))

    return vault_balance


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


def _get_deposits_amounts(vault_assets: int, validator_type: ValidatorType) -> list[Gwei]:
    """Returns a list of amounts in Gwei for each validator to be registered."""
    if vault_assets < MIN_ACTIVATION_BALANCE:
        return []
    if validator_type == ValidatorType.V1:
        return [MIN_ACTIVATION_BALANCE_GWEI] * (vault_assets // MIN_ACTIVATION_BALANCE)
    amounts = []
    while vault_assets >= MAX_EFFECTIVE_BALANCE:
        amounts.append(MAX_EFFECTIVE_BALANCE_GWEI)
        vault_assets -= MAX_EFFECTIVE_BALANCE
    if vault_assets >= MIN_ACTIVATION_BALANCE:
        amounts.append(Gwei(int(Web3.from_wei(vault_assets, 'gwei'))))
    return amounts


def _get_funding_amounts(
    vault_validators: dict[HexStr, Gwei], funding_amount: Gwei
) -> dict[HexStr, Gwei]:
    result = {}
    for public_key, balance in sorted(
        vault_validators.items(), key=lambda item: item[1], reverse=True
    ):
        remaining_capacity = MAX_EFFECTIVE_BALANCE_GWEI - balance
        if remaining_capacity >= settings.min_deposit_amount:
            val_amount = min(remaining_capacity, funding_amount)
            result[public_key] = Gwei(val_amount)
            funding_amount = Gwei(funding_amount - val_amount)
        if funding_amount < settings.min_deposit_amount:
            break
    return result
