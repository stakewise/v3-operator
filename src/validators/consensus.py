import logging
from collections import defaultdict
from itertools import batched

from eth_typing import HexStr
from sw_utils import ValidatorStatus
from sw_utils.consensus import EXITED_STATUSES
from web3.types import Gwei

from src.common.clients import consensus_client
from src.common.consensus import get_chain_latest_head
from src.common.consolidations import get_pending_consolidations
from src.config.settings import settings
from src.validators.database import VaultValidatorCrud
from src.validators.event_processors import get_latest_vault_v2_validator_public_keys
from src.validators.typings import ConsensusValidator

EXITING_STATUSES = [
    ValidatorStatus.ACTIVE_EXITING,
    ValidatorStatus.ACTIVE_SLASHED,
] + EXITED_STATUSES

logger = logging.getLogger(__name__)


# pylint: disable-next=too-many-locals
async def fetch_funding_validators_balances() -> dict[HexStr, Gwei]:
    """
    Retrieves the consensus balances of vault validators eligible for funding.
    Includes balances from pending deposits that have not yet been processed by the
    consensus node. Accounts for pending consolidations.
    """
    vault_public_keys = {v.public_key for v in VaultValidatorCrud().get_vault_validators()}
    vault_public_keys.update(await get_latest_vault_v2_validator_public_keys(settings.vault))
    if not vault_public_keys:
        return {}

    # Fetch consensus validators and pending consolidations from one consistent snapshot
    chain_head = await get_chain_latest_head()
    slot = str(chain_head.slot)
    consensus_validators = await fetch_consensus_validators(list(vault_public_keys), slot=slot)
    pending_consolidations = await get_pending_consolidations(chain_head, consensus_validators)

    # Filter compounding and remove exiting/withdrawn validators, as they are not
    # eligible for funding.
    validators_balances: dict[HexStr, Gwei] = {}
    ineligible_public_keys: set[HexStr] = set()
    index_to_validator: dict[int, ConsensusValidator] = {}
    for validator in consensus_validators:
        index_to_validator[validator.index] = validator
        if validator.is_compounding and validator.status not in EXITING_STATUSES:
            validators_balances[validator.public_key] = validator.balance
        else:
            ineligible_public_keys.add(validator.public_key)

    # Exclude pending consolidation sources from funding and credit their balances
    # to the targets; drop targets whose source balance is unknown.
    for cons in pending_consolidations:
        target = index_to_validator.get(cons.target_index)
        source = index_to_validator.get(cons.source_index)
        if source is None:
            if target is not None:
                validators_balances.pop(target.public_key, None)
                ineligible_public_keys.add(target.public_key)
        else:
            validators_balances.pop(source.public_key, None)
            ineligible_public_keys.add(source.public_key)
            if target is not None and target.public_key in validators_balances:
                validators_balances[target.public_key] = Gwei(
                    validators_balances[target.public_key] + source.balance
                )

    # Keys not yet known to the consensus node are eligible too,
    # their balances come solely from pending deposits.
    eligible_public_keys = vault_public_keys - ineligible_public_keys

    # Add balances from pending deposits that are not yet reflected in the consensus node.
    pending_deposits_amounts = await fetch_compounding_pending_deposits_amounts(
        public_keys=eligible_public_keys, slot=slot
    )
    for public_key, amount in pending_deposits_amounts.items():
        validators_balances[public_key] = Gwei(
            validators_balances.get(public_key, Gwei(0)) + amount
        )

    return validators_balances


async def fetch_compounding_pending_deposits_amounts(
    public_keys: set[HexStr], slot: str
) -> dict[HexStr, Gwei]:
    """
    Sums pending-deposit-queue amounts (Gwei) per pubkey, restricted to ``public_keys``.
    Only deposits with compounding (0x02) withdrawal credentials are counted:
    non-0x02 deposits are still processed by the CL, but they never contribute
    fundable compounding balance, so counting them would overstate top-up capacity.
    """
    if not public_keys:
        return {}

    pending_amounts: dict[HexStr, Gwei] = defaultdict(lambda: Gwei(0))
    all_pending_deposits = await consensus_client.get_pending_deposits(slot)
    for deposit in all_pending_deposits:
        public_key: HexStr = deposit['pubkey']
        if public_key not in public_keys:
            continue
        if not deposit['withdrawal_credentials'].startswith('0x02'):
            continue
        pending_amounts[public_key] = Gwei(pending_amounts[public_key] + int(deposit['amount']))

    return dict(pending_amounts)


async def fetch_pending_deposits_amounts(public_keys: set[HexStr], slot: str) -> dict[HexStr, Gwei]:
    """
    Sums pending-deposit-queue amounts (Gwei) per pubkey, restricted to ``public_keys``.
    """
    if not public_keys:
        return {}

    pending_amounts: dict[HexStr, Gwei] = defaultdict(lambda: Gwei(0))
    all_pending_deposits = await consensus_client.get_pending_deposits(slot)
    for deposit in all_pending_deposits:
        public_key: HexStr = deposit['pubkey']
        if public_key not in public_keys:
            continue
        pending_amounts[public_key] = Gwei(pending_amounts[public_key] + int(deposit['amount']))

    return dict(pending_amounts)


async def fetch_consensus_validators(
    validator_ids: list[HexStr] | list[str], slot: str = 'head'
) -> list[ConsensusValidator]:
    validators = []
    for chunk_keys in batched(validator_ids, settings.validators_fetch_chunk_size):
        beacon_validators = await consensus_client.get_validators_by_ids(
            validator_ids=chunk_keys, state_id=slot
        )
        for beacon_validator in beacon_validators['data']:
            validators.append(ConsensusValidator.from_consensus_data(beacon_validator))

    return validators
