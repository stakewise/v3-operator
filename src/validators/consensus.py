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
from src.common.typings import PendingConsolidation
from src.config.settings import settings
from src.validators.database import VaultValidatorCrud
from src.validators.event_processors import get_latest_vault_v2_validator_public_keys
from src.validators.typings import ConsensusValidator

EXITING_STATUSES = [
    ValidatorStatus.ACTIVE_EXITING,
    ValidatorStatus.ACTIVE_SLASHED,
] + EXITED_STATUSES

logger = logging.getLogger(__name__)


async def fetch_funding_validators_balances() -> dict[HexStr, Gwei]:
    """
    Retrieves the consensus balances of vault validators eligible for funding.
    Includes balances from pending deposits that have not yet been processed by the
    consensus node.

    Pending consolidations are folded in too: a consolidation source keeps compounding
    until it is processed, so it is excluded from the fundable set entirely, and its
    balance is credited onto the target instead of the target's raw (pre-consolidation)
    balance, since that is what the target will actually hold once the consolidation
    lands. If a source's balance can't be determined, the target is dropped from the
    fundable set rather than guessed at.
    """
    vault_public_keys = {v.public_key for v in VaultValidatorCrud().get_vault_validators()}
    non_finalized_public_keys = await get_latest_vault_v2_validator_public_keys(settings.vault)
    vault_public_keys.update(non_finalized_public_keys)
    if not vault_public_keys:
        return {}

    # Fetch consensus validators and pending consolidations from one consistent snapshot
    chain_head = await get_chain_latest_head()
    slot = str(chain_head.slot)
    consensus_validators = await fetch_consensus_validators(list(vault_public_keys), slot=slot)
    pending_consolidations = await get_pending_consolidations(chain_head, consensus_validators)
    incoming_balances, unfundable_target_public_keys, consolidating_source_public_keys = (
        _fold_pending_consolidations(consensus_validators, pending_consolidations)
    )

    # Filter compounding and remove exiting/withdrawn/consolidation-source validators,
    # as they are not eligible for funding. Consolidation targets get the incoming
    # source balance added on top of their own.
    validators_balances, ineligible_public_keys = _build_fundable_balances(
        consensus_validators, incoming_balances, consolidating_source_public_keys
    )

    # Keys not yet known to the consensus node are eligible too,
    # their balances come solely from pending deposits.
    eligible_public_keys = vault_public_keys - ineligible_public_keys

    # Add balances from pending deposits that are not yet reflected in the consensus node.
    pending_deposits_amounts = await fetch_compounding_pending_deposits_amounts(
        public_keys=eligible_public_keys, slot=slot
    )
    return _finalize_validators_balances(
        validators_balances, pending_deposits_amounts, unfundable_target_public_keys
    )


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


def _fold_pending_consolidations(
    consensus_validators: list[ConsensusValidator],
    pending_consolidations: list[PendingConsolidation],
) -> tuple[defaultdict[int, Gwei], set[HexStr], set[HexStr]]:
    """
    Sums each pending consolidation's source balance onto its target's incoming balance,
    since that is what the target will actually hold once the consolidation is processed.
    Also reports which public keys must be excluded from the fundable set: consolidation
    sources (always, since they keep compounding until processed), and targets whose
    source balance is unknown (conservatively excluded rather than guessed at).
    """
    index_to_balance: dict[int, Gwei] = {val.index: val.balance for val in consensus_validators}
    index_to_public_key: dict[int, HexStr] = {
        val.index: val.public_key for val in consensus_validators
    }

    incoming_balances: defaultdict[int, Gwei] = defaultdict(lambda: Gwei(0))
    unfundable_target_public_keys: set[HexStr] = set()
    consolidating_source_public_keys: set[HexStr] = set()
    for cons in pending_consolidations:
        source_public_key = index_to_public_key.get(cons.source_index)
        if source_public_key is not None:
            consolidating_source_public_keys.add(source_public_key)

        source_balance = index_to_balance.get(cons.source_index)
        if source_balance is None:
            target_public_key = index_to_public_key.get(cons.target_index)
            if target_public_key is not None:
                unfundable_target_public_keys.add(target_public_key)
            continue
        incoming_balances[cons.target_index] = Gwei(
            incoming_balances[cons.target_index] + source_balance
        )

    return incoming_balances, unfundable_target_public_keys, consolidating_source_public_keys


def _build_fundable_balances(
    consensus_validators: list[ConsensusValidator],
    incoming_balances: defaultdict[int, Gwei],
    consolidating_source_public_keys: set[HexStr],
) -> tuple[dict[HexStr, Gwei], set[HexStr]]:
    validators_balances: dict[HexStr, Gwei] = {}
    ineligible_public_keys: set[HexStr] = set(consolidating_source_public_keys)
    for validator in consensus_validators:
        if validator.public_key in consolidating_source_public_keys:
            continue
        if validator.is_compounding and validator.status not in EXITING_STATUSES:
            validators_balances[validator.public_key] = Gwei(
                validator.balance + incoming_balances[validator.index]
            )
        else:
            ineligible_public_keys.add(validator.public_key)

    return validators_balances, ineligible_public_keys


def _finalize_validators_balances(
    validators_balances: dict[HexStr, Gwei],
    pending_deposits_amounts: dict[HexStr, Gwei],
    unfundable_target_public_keys: set[HexStr],
) -> dict[HexStr, Gwei]:
    for public_key, amount in pending_deposits_amounts.items():
        validators_balances[public_key] = Gwei(
            validators_balances.get(public_key, Gwei(0)) + amount
        )

    for target_public_key in unfundable_target_public_keys:
        validators_balances.pop(target_public_key, None)

    return validators_balances
