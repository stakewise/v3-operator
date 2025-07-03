import logging

from eth_typing import ChecksumAddress, HexStr
from eth_utils import add_0x_prefix
from sw_utils import ValidatorStatus, chunkify
from sw_utils.consensus import EXITED_STATUSES
from web3 import Web3
from web3.types import BlockNumber, Gwei, Wei

from src.common.clients import consensus_client, execution_client
from src.common.contracts import VaultContract
from src.config.settings import settings
from src.validators.database import VaultValidatorCrud
from src.validators.typings import VaultValidator

EXITING_STATUSES = [ValidatorStatus.ACTIVE_EXITING] + EXITED_STATUSES

logger = logging.getLogger(__name__)


async def fetch_compounding_validators_balances(
    vault_address: ChecksumAddress,
) -> dict[HexStr, Gwei]:
    """
    Retrieves the actual balances of compounding validators in the vault.
    """
    vault_contract = VaultContract(vault_address)
    block_number = await execution_client.eth.get_block_number()

    vault_validators = VaultValidatorCrud().get_vault_validators(vault_address)
    vault_public_keys = [key.public_key for key in vault_validators]
    active_validator_balances, non_activated_public_keys = (
        await _fetch_compounding_balances_and_non_activated_keys(vault_public_keys)
    )

    non_activated_balances = await _get_non_activated_balances(
        vault_validators=vault_validators,
        non_activated_public_keys=non_activated_public_keys,
        vault_contract=vault_contract,
        block_number=block_number,
    )

    return active_validator_balances | non_activated_balances


async def _fetch_compounding_balances_and_non_activated_keys(
    public_keys: list[HexStr],
) -> tuple[dict[HexStr, Gwei], list[HexStr]]:
    """
    Returns a tuple of active compounding validators with their balances
    and a list of public keys not yet registered in the consensus client
    """
    validators = {}
    consensus_public_keys = []
    for chunk_keys in chunkify(public_keys, settings.validators_fetch_chunk_size):
        beacon_validators = await consensus_client.get_validators_by_ids(chunk_keys)
        for beacon_validator in beacon_validators['data']:
            public_key = add_0x_prefix(beacon_validator['validator']['pubkey'])
            consensus_public_keys.append(public_key)
            withdrawal_credentials = beacon_validator['validator']['withdrawal_credentials']
            if not withdrawal_credentials.startswith('0x02'):
                continue

            status = ValidatorStatus(beacon_validator['status'])
            if status in EXITING_STATUSES:
                continue

            public_key = add_0x_prefix(beacon_validator['validator']['pubkey'])
            validators[public_key] = Gwei(int(beacon_validator['balance']))

    return validators, list(set(public_keys) - set(consensus_public_keys))


async def _get_non_activated_balances(
    vault_validators: list[VaultValidator],
    non_activated_public_keys: list[HexStr],
    vault_contract: VaultContract,
    block_number: BlockNumber,
) -> dict[HexStr, Gwei]:
    """Fetches the start balances for validators not yet registered in the consensus client."""
    if not non_activated_public_keys:
        return {}

    min_funding_block = min(
        v.block_number for v in vault_validators if v.public_key in non_activated_public_keys
    )
    compounding_event_data = await vault_contract.get_compounding_validators_events(
        from_block=min_funding_block,
        to_block=block_number,
    )
    non_activated_balances = {
        v.public_key: v.amount
        for v in compounding_event_data
        if v.public_key in non_activated_public_keys
    }
    funding_event_data = await vault_contract.get_funding_events(
        from_block=min_funding_block,
        to_block=block_number,
    )

    for funding in funding_event_data:
        if funding.public_key in non_activated_balances:
            non_activated_balances[funding.public_key] = Wei(
                non_activated_balances[funding.public_key] + funding.amount
            )
    return {
        public_key: Gwei(int(Web3.from_wei(amount_wei, 'gwei')))
        for public_key, amount_wei in non_activated_balances.items()
    }
