import logging
from typing import Sequence, cast

from eth_typing import HexStr
from sw_utils import IpfsFetchClient, convert_to_mgno
from sw_utils.networks import GNO_NETWORKS
from sw_utils.typings import Bytes32
from web3 import Web3
from web3.types import BlockNumber, ChecksumAddress, Gwei

from src.common.clients import execution_client
from src.common.contracts import VaultContract, validators_registry_contract
from src.common.execution import build_gas_manager, get_protocol_config
from src.common.harvest import get_harvest_params
from src.common.metrics import metrics
from src.common.typings import HarvestParams, ValidatorType
from src.config.settings import (
    MAX_EFFECTIVE_BALANCE_GWEI,
    MIN_ACTIVATION_BALANCE_GWEI,
    ValidatorsRegistrationMode,
    settings,
)
from src.validators.consensus import fetch_compounding_validators_balances
from src.validators.database import NetworkValidatorCrud
from src.validators.exceptions import (
    EmptyRelayerResponseException,
    MissingAvailableValidatorsException,
)
from src.validators.execution import get_withdrawable_assets
from src.validators.keystores.base import BaseKeystore
from src.validators.metrics import update_unused_validator_keys_metric
from src.validators.oracles import poll_validation_approval
from src.validators.register_validators import fund_validators, register_validators
from src.validators.relayer import RelayerClient
from src.validators.typings import NetworkValidator, Validator
from src.validators.utils import (
    get_validators_for_funding,
    get_validators_for_registration,
)
from src.validators.validators_manager import get_validators_manager_signature

logger = logging.getLogger(__name__)


class ValidatorRegistrationSubtask:
    def __init__(
        self,
        keystore: BaseKeystore | None,
        relayer: RelayerClient | None,
    ):
        self.keystore = keystore
        self.relayer = relayer

    async def process(self) -> None:
        if self.keystore:
            await update_unused_validator_keys_metric(
                keystore=self.keystore,
            )
        # check and register new validators
        for vault_address in settings.vaults:
            await process_validators(
                vault_address=vault_address,
                keystore=self.keystore,
                relayer=self.relayer,
            )


async def process_validators(
    vault_address: ChecksumAddress,
    keystore: BaseKeystore | None,
    relayer: RelayerClient | None = None,
) -> None:
    """
    Calculates vault assets, requests oracles approval, submits registration tx
    """
    harvest_params = await get_harvest_params(vault_address)

    vault_assets = await get_vault_assets(
        vault_address=vault_address, harvest_params=harvest_params
    )

    if vault_assets < settings.min_deposit_amount_gwei:
        return None

    gas_manager = build_gas_manager()
    if not await gas_manager.check_gas_price():
        return None

    if settings.validator_type == ValidatorType.V1:
        await register_new_validators(
            vault_address=vault_address,
            vault_assets=vault_assets,
            harvest_params=harvest_params,
            keystore=keystore,
            relayer=relayer,
        )
        return

    compounding_validators_balances = await fetch_compounding_validators_balances(vault_address)
    funding_amounts = _get_funding_amounts(
        compounding_validators_balances=compounding_validators_balances,
        vault_assets=vault_assets,
    )

    if funding_amounts:
        if not await _is_funding_interval_passed(vault_address):
            return

        try:
            tx_hash = await fund_compounding_validators(
                vault_address=vault_address,
                funding_amounts=funding_amounts,
                keystore=keystore,
                harvest_params=harvest_params,
                relayer=relayer,
            )
            if not tx_hash:
                return

            vault_assets = Gwei(max(vault_assets - sum(funding_amounts.values()), 0))
        except EmptyRelayerResponseException:
            return

    await register_new_validators(
        vault_address=vault_address,
        vault_assets=vault_assets,
        harvest_params=harvest_params,
        keystore=keystore,
        relayer=relayer,
    )


async def fund_compounding_validators(
    vault_address: ChecksumAddress,
    keystore: BaseKeystore | None,
    funding_amounts: dict[HexStr, Gwei],
    harvest_params: HarvestParams | None,
    relayer: RelayerClient | None = None,
) -> HexStr | None:
    """
    Funds vault compounding validators with the specified amount.
    """
    logger.info('Started funding of %d validator(s)', len(funding_amounts))
    validators_manager_signature = HexStr('0x')
    if settings.validators_registration_mode == ValidatorsRegistrationMode.AUTO:
        validators = await get_validators_for_funding(
            funding_amounts=funding_amounts,
            keystore=cast(BaseKeystore, keystore),
            vault_address=vault_address,
        )
    else:
        # fetch validators and signature from relayer
        validators_response = await cast(RelayerClient, relayer).fund_validators(
            funding_amounts=funding_amounts,
            vault_address=vault_address,
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
    return tx_hash


# pylint: disable-next=too-many-locals
async def register_new_validators(
    vault_address: ChecksumAddress,
    vault_assets: Gwei,
    harvest_params: HarvestParams | None,
    keystore: BaseKeystore | None,
    relayer: RelayerClient | None = None,
) -> HexStr | None:
    validators_amounts = _get_deposits_amounts(vault_assets, settings.validator_type)
    validators_count = len(validators_amounts)
    if not validators_amounts:
        # not enough balance to register validators
        return None

    # get latest config
    protocol_config = await get_protocol_config()

    validators_batch_size = min(protocol_config.validators_approval_batch_limit, validators_count)
    validators: Sequence[Validator]

    if settings.validators_registration_mode == ValidatorsRegistrationMode.AUTO:
        validators = await get_validators_for_registration(
            keystore=cast(BaseKeystore, keystore),
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
                    'to proceed with registration. '
                    'To register additional validators, you must generate new keystores.',
                )
            return None
    else:
        try:
            validators_response = await cast(RelayerClient, relayer).register_validators(
                vault_address=vault_address,
                amounts=validators_amounts[:validators_batch_size],
            )
        except MissingAvailableValidatorsException:
            if not settings.disable_available_validators_warnings:
                logger.warning(
                    'There are no available public keys '
                    'in current keystores files '
                    'to proceed with registration. '
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

    logger.info(
        'Started registration of %d %s validator(s)', len(validators), settings.validator_type.value
    )

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
) -> Gwei:
    vault_assets = await get_withdrawable_assets(
        vault_address=vault_address, harvest_params=harvest_params
    )
    if settings.network in GNO_NETWORKS:
        # apply GNO -> mGNO exchange rate
        vault_assets = convert_to_mgno(vault_assets)

    metrics.stakeable_assets.labels(network=settings.network).set(int(vault_assets))

    return Gwei(int(Web3.from_wei(vault_assets, 'gwei')))


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


def _get_deposits_amounts(vault_assets: Gwei, validator_type: ValidatorType) -> list[Gwei]:
    """Returns a list of amounts in Gwei for each validator to be registered."""
    if vault_assets < MIN_ACTIVATION_BALANCE_GWEI:
        return []
    if validator_type == ValidatorType.V1:
        return [MIN_ACTIVATION_BALANCE_GWEI] * (vault_assets // MIN_ACTIVATION_BALANCE_GWEI)
    amounts = []
    while vault_assets >= MAX_EFFECTIVE_BALANCE_GWEI:
        amounts.append(MAX_EFFECTIVE_BALANCE_GWEI)
        vault_assets = Gwei(vault_assets - MAX_EFFECTIVE_BALANCE_GWEI)
    if vault_assets >= MIN_ACTIVATION_BALANCE_GWEI:
        amounts.append(vault_assets)
    return amounts


def _get_funding_amounts(
    compounding_validators_balances: dict[HexStr, Gwei], vault_assets: Gwei
) -> dict[HexStr, Gwei]:
    result = {}
    for public_key, balance in sorted(
        compounding_validators_balances.items(), key=lambda item: item[1], reverse=True
    ):
        remaining_capacity = MAX_EFFECTIVE_BALANCE_GWEI - balance
        if remaining_capacity >= settings.min_deposit_amount_gwei:
            val_amount = min(remaining_capacity, vault_assets)
            result[public_key] = Gwei(val_amount)
            vault_assets = Gwei(vault_assets - val_amount)
        if vault_assets < settings.min_deposit_amount_gwei:
            break
    return result


async def _is_funding_interval_passed(vault_address: ChecksumAddress) -> bool:
    """
    Check if the required interval has passed since the last funding event.
    Mitigate gas griefing attack
    """
    blocks_delay = settings.min_deposit_delay // settings.network_config.SECONDS_PER_BLOCK
    to_block = await execution_client.eth.get_block_number()
    from_block = BlockNumber(to_block - blocks_delay)
    funding_events = await VaultContract(vault_address).get_funding_events(from_block, to_block)
    return len(funding_events) == 0
