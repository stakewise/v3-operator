import logging
from collections import defaultdict
from dataclasses import replace
from itertools import batched
from typing import Collection, cast

from eth_typing import HexStr
from sw_utils import ChainHead, ValidatorStatus
from sw_utils.consensus import EXITED_STATUSES
from web3.types import Gwei

from src.common.clients import consensus_client
from src.common.consensus import get_chain_latest_head
from src.common.consolidations import get_pending_consolidations
from src.common.typings import PendingConsolidation
from src.config.settings import settings
from src.validators.database import VaultValidatorCrud
from src.validators.event_processors import get_latest_vault_v2_validator_public_keys
from src.validators.typings import ConsensusValidator, ValidatorConsolidationData

EXITING_STATUSES = [
    ValidatorStatus.ACTIVE_EXITING,
    ValidatorStatus.ACTIVE_SLASHED,
] + EXITED_STATUSES

# Index assigned to validators that are not present in the beacon state yet
# and were built solely from their pending deposits.
UNKNOWN_VALIDATOR_INDEX = -1

logger = logging.getLogger(__name__)


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

    validators = await build_consensus_validators(
        public_keys=vault_public_keys,
        with_pending_deposits=True,
        with_consolidations=True,
        compounding_deposits_only=True,
    )

    validators_balances: dict[HexStr, Gwei] = {}
    for validator in validators:
        # Non-compounding and exiting/withdrawn validators are not eligible for funding.
        if not validator.is_compounding or validator.status in EXITING_STATUSES:
            continue

        consolidation_data = cast(ValidatorConsolidationData, validator.consolidation_data)

        # Consolidation sources are drained into their targets, so they are not funded.
        if consolidation_data.is_source:
            continue

        # Drop targets whose source balance is unknown instead of guessing
        # their post-consolidation balance.
        if consolidation_data.is_target and consolidation_data.target_balance is None:
            continue

        validators_balances[validator.public_key] = Gwei(
            validator.balance
            + (validator.pending_balance or 0)
            + (consolidation_data.target_balance or 0)
        )

    return validators_balances


async def build_consensus_validators(
    public_keys: Collection[HexStr],
    chain_head: ChainHead | None = None,
    with_pending_deposits: bool = False,
    with_consolidations: bool = False,
    compounding_deposits_only: bool = False,
) -> list[ConsensusValidator]:
    """
    Fetches the consensus validators for ``public_keys`` and optionally enriches them with
    the pending deposits and pending consolidations data from the same chain snapshot.

    ``with_pending_deposits`` fills in ``pending_balance`` and additionally returns validators
    that are not present in the beacon state yet, but already have pending deposits. Such
    validators get ``UNKNOWN_VALIDATOR_INDEX`` and their withdrawal credentials come from
    the deposit itself.
    ``compounding_deposits_only`` restricts pending deposits to the ones with compounding
    (0x02) withdrawal credentials: non-0x02 deposits are still processed by the CL, but they
    never contribute fundable compounding balance.

    ``with_consolidations`` fills in ``consolidation_data``, which stays ``None`` when the
    data was not requested.
    """
    if not public_keys:
        return []

    chain_head = chain_head or await get_chain_latest_head()
    slot = str(chain_head.slot)
    validators = await fetch_consensus_validators(list(public_keys), slot=slot)

    if with_consolidations:
        validators = _apply_pending_consolidations(
            validators=validators,
            pending_consolidations=await get_pending_consolidations(chain_head, validators),
        )

    if with_pending_deposits:
        validators, new_validators = await apply_pending_deposits(
            validators=validators,
            public_keys=set(public_keys),
            slot=slot,
            compounding_deposits_only=compounding_deposits_only,
        )
        if with_consolidations:
            # Fill in empty consolidation data for consistency with the rest of the
            # returned validators. Validators that are not in the beacon state yet
            # can't take part in consolidations.
            new_validators = [
                replace(
                    val,
                    consolidation_data=ValidatorConsolidationData(is_source=False, is_target=False),
                )
                for val in new_validators
            ]
        validators += new_validators

    return validators


def _apply_pending_consolidations(
    validators: list[ConsensusValidator], pending_consolidations: list[PendingConsolidation]
) -> list[ConsensusValidator]:
    """
    Returns a copy of ``validators``, in the same order, with ``consolidation_data``
    filled in. ``target_balance`` stays ``None`` when at least one of the target's sources
    is not among the fetched validators, i.e. its balance is unknown.
    """
    index_to_validator = {val.index: val for val in validators}

    source_indexes: set[int] = set()
    target_indexes: set[int] = set()
    target_balances: dict[int, Gwei] = defaultdict(lambda: Gwei(0))
    unknown_source_targets: set[int] = set()

    for cons in pending_consolidations:
        source = index_to_validator.get(cons.source_index)
        if source is not None:
            source_indexes.add(cons.source_index)

        if cons.target_index not in index_to_validator:
            continue
        target_indexes.add(cons.target_index)

        if source is None:
            # The source balance is unknown, so the target balance can't be determined
            unknown_source_targets.add(cons.target_index)
        else:
            target_balances[cons.target_index] = Gwei(
                target_balances[cons.target_index] + source.balance
            )

    enriched_validators = []
    for val in validators:
        if val.index in unknown_source_targets:
            target_balance = None
        else:
            target_balance = target_balances.get(val.index)

        consolidation_data = ValidatorConsolidationData(
            is_source=val.index in source_indexes,
            is_target=val.index in target_indexes,
            target_balance=target_balance,
        )
        enriched_validators.append(replace(val, consolidation_data=consolidation_data))

    return enriched_validators


async def apply_pending_deposits(
    validators: list[ConsensusValidator],
    public_keys: set[HexStr],
    slot: str,
    compounding_deposits_only: bool = False,
) -> tuple[list[ConsensusValidator], list[ConsensusValidator]]:
    """
    Returns a tuple of:
    1) a copy of ``validators``, in the same order, with ``pending_balance`` filled in
    2) validators that are not present in the beacon state yet, but already have
       pending deposits

    Can be called separately from `build_consensus_validators` to delay fetching the
    pending deposit queue until it is really needed.
    """
    known_public_keys = {val.public_key for val in validators}
    pending_balances: dict[HexStr, Gwei] = defaultdict(lambda: Gwei(0))
    new_credentials: dict[HexStr, HexStr] = {}

    for deposit in await consensus_client.get_pending_deposits(slot):
        public_key: HexStr = deposit['pubkey']
        if public_key not in public_keys:
            continue

        withdrawal_credentials: HexStr = deposit['withdrawal_credentials']
        if compounding_deposits_only and not withdrawal_credentials.startswith('0x02'):
            continue

        pending_balances[public_key] = Gwei(pending_balances[public_key] + int(deposit['amount']))
        if public_key not in known_public_keys:
            # Validator is not present in the beacon state yet.
            # A validator's withdrawal credentials are set
            # by the deposit that creates it, and later deposits in the queue
            # for the same pubkey don't change them.
            new_credentials.setdefault(public_key, withdrawal_credentials)

    enriched_validators = [
        replace(val, pending_balance=pending_balances.get(val.public_key)) for val in validators
    ]
    new_validators = [
        ConsensusValidator(
            index=UNKNOWN_VALIDATOR_INDEX,
            public_key=public_key,
            balance=Gwei(0),
            withdrawal_credentials=withdrawal_credentials,
            status=ValidatorStatus.PENDING_INITIALIZED,
            activation_epoch=settings.network_config.FAR_FUTURE_EPOCH,
            pending_balance=pending_balances[public_key],
        )
        for public_key, withdrawal_credentials in new_credentials.items()
    ]
    return enriched_validators, new_validators


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
