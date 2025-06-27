import logging
from typing import cast

from eth_typing import ChecksumAddress, HexStr
from eth_utils import add_0x_prefix
from sw_utils import ValidatorStatus, chunkify
from sw_utils.consensus import EXITED_STATUSES
from web3 import Web3
from web3.types import BlockNumber, Gwei, Wei

from src.common.clients import consensus_client, execution_client
from src.common.contracts import VaultContract
from src.config.settings import settings

EXITING_STATUSES = [ValidatorStatus.ACTIVE_EXITING] + EXITED_STATUSES

logger = logging.getLogger(__name__)


async def fetch_compounding_validators_balances(
    vault_address: ChecksumAddress,
) -> dict[HexStr, Gwei]:
    """
    Retrieves the actual balances of can be compounding validators in the vault.
    """
    vault_contract = VaultContract(vault_address)
    current_block = await execution_client.eth.get_block_number()
    validators_event_data = await vault_contract.get_compounding_validators_events(
        from_block=settings.network_config.KEEPER_GENESIS_BLOCK,
        to_block=current_block,
    )
    registered_public_keys = [key.public_key for key in validators_event_data]
    active_validator_balances, non_activated_public_keys = (
        await _fetch_active_balances_and_non_registered_keys(registered_public_keys)
    )
    min_funding_block = min(
        cast(BlockNumber, v.block_number)
        for v in validators_event_data
        if v.public_key in non_activated_public_keys
    )
    funding_event_data = await vault_contract.get_funding_events(
        from_block=min_funding_block,
        to_block=current_block,
    )

    non_activated_balances = {
        v.public_key: v.amount
        for v in validators_event_data
        if v.public_key in non_activated_public_keys
    }
    for funding in funding_event_data:
        if funding.public_key in non_activated_balances:
            non_activated_balances[funding.public_key] = Wei(
                non_activated_balances[funding.public_key] + funding.amount
            )

    result_balances: dict[HexStr, Gwei] = {}
    for public_key, amount_gwei in active_validator_balances.items():
        result_balances[public_key] = amount_gwei
    for public_key, amount_wei in non_activated_balances.items():
        result_balances[public_key] = Gwei(int(Web3.from_wei(amount_wei, 'gwei')))

    return result_balances


async def _fetch_active_balances_and_non_registered_keys(
    public_keys: list[HexStr],
) -> tuple[dict[HexStr, Gwei], list[HexStr]]:
    """
    Returns a tuple of active validators with their balances
    and a list of public keys not yet registered in the consensus client
    """
    validators = {}
    consensus_public_keys = []
    for chunk_keys in chunkify(public_keys, settings.validators_fetch_chunk_size):
        beacon_validators = await consensus_client.get_validators_by_ids(chunk_keys)
        for beacon_validator in beacon_validators['data']:
            public_key = add_0x_prefix(beacon_validator['validator']['pubkey'])
            consensus_public_keys.append(public_key)
            status = ValidatorStatus(beacon_validator['status'])
            if status in EXITING_STATUSES:
                continue

            public_key = add_0x_prefix(beacon_validator['validator']['pubkey'])
            validators[public_key] = Gwei(int(beacon_validator['balance']))

    return validators, list(set(public_keys) - set(consensus_public_keys))
