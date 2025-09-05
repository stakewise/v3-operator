import logging

from eth_typing import ChecksumAddress, HexStr
from sw_utils import ValidatorStatus, chunkify
from sw_utils.consensus import EXITED_STATUSES
from web3.types import Gwei

from src.common.clients import consensus_client
from src.config.settings import settings
from src.validators.database import VaultValidatorCrud
from src.validators.execution import get_latest_vault_v2_validator_public_keys
from src.validators.typings import ConsensusValidator

EXITING_STATUSES = [ValidatorStatus.ACTIVE_EXITING] + EXITED_STATUSES

logger = logging.getLogger(__name__)


async def fetch_compounding_validators_balances(
    vault_address: ChecksumAddress,
) -> dict[HexStr, Gwei]:
    """
    Retrieves the actual balances of compounding validators in the vault.
    Also includes balances from pending deposits
    that have not yet been processed by the consensus node.
    """
    vault_public_keys = {
        key.public_key for key in VaultValidatorCrud().get_vault_validators(vault_address)
    }
    non_finalized_public_keys = await get_latest_vault_v2_validator_public_keys(vault_address)
    vault_public_keys.update(non_finalized_public_keys)
    if not vault_public_keys:
        return {}

    consensus_block = await consensus_client.get_block('head')
    slot = consensus_block['data']['message']['slot']
    consensus_validators = await fetch_consensus_validators(list(vault_public_keys), slot=slot)

    validators_balances = {
        v.public_key: v.balance
        for v in consensus_validators
        if v.is_compounding and v.status not in EXITING_STATUSES
    }

    all_pending_deposits = await consensus_client.get_pending_deposits(slot)
    for deposit in all_pending_deposits:
        public_key, amount = deposit['pubkey'], int(deposit['amount'])
        if public_key not in vault_public_keys:
            continue
        if not deposit['withdrawal_credentials'].startswith('0x02'):
            continue
        if validators_balances.get(public_key):
            validators_balances[public_key] = Gwei(validators_balances[public_key] + amount)
        else:
            validators_balances[public_key] = Gwei(amount)

    return validators_balances


async def fetch_consensus_validators(
    validator_ids: list[HexStr] | list[str], slot: str = 'head'
) -> list[ConsensusValidator]:
    validators = []
    for chunk_keys in chunkify(validator_ids, settings.validators_fetch_chunk_size):
        beacon_validators = await consensus_client.get_validators_by_ids(
            validator_ids=chunk_keys, state_id=slot
        )
        for beacon_validator in beacon_validators['data']:
            validators.append(ConsensusValidator.from_consensus_data(beacon_validator))

    return validators
