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
    Also includes non-activated validator balances.
    """
    vault_public_keys = {
        key.public_key for key in VaultValidatorCrud().get_vault_validators(vault_address)
    }
    non_finalized_public_keys = await get_latest_vault_v2_validator_public_keys(vault_address)
    vault_public_keys.update(non_finalized_public_keys)
    if not vault_public_keys:
        return {}
    consensus_validators = await fetch_consensus_validators(list(vault_public_keys))

    active_validator_balances = {
        v.public_key: v.balance
        for v in consensus_validators
        if v.is_compounding and v.status not in EXITING_STATUSES
    }

    all_pending_deposits = await consensus_client.get_pending_deposits()
    pending_deposits = {
        deposit['pubkey']: Gwei(int(deposit['amount']))
        for deposit in all_pending_deposits
        if deposit['pubkey'] in vault_public_keys
        and deposit['withdrawal_credentials'].startswith('0x02')
    }

    # sum active balances and pending deposits
    result: dict[HexStr, Gwei] = {}
    for d in [active_validator_balances, pending_deposits]:
        for k in d.keys():
            result[k] = Gwei(result.get(k, 0) + d[k])
    return result


async def fetch_consensus_validators(
    public_keys: list[HexStr],
) -> list[ConsensusValidator]:
    validators = []
    for chunk_keys in chunkify(public_keys, settings.validators_fetch_chunk_size):
        beacon_validators = await consensus_client.get_validators_by_ids(chunk_keys)
        for beacon_validator in beacon_validators['data']:
            validators.append(ConsensusValidator.from_consensus_data(beacon_validator))

    return validators
