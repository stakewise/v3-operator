import logging
from collections import defaultdict
from itertools import batched
from typing import Collection

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
from src.validators.typings import ConsensusValidator

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

        # Consolidation sources are drained into their targets, so they are not funded.
        if validator.is_consolidation_source:
            continue

        # Drop targets whose source balance is unknown instead of guessing
        # their post-consolidation balance.
        if validator.is_consolidation_target and validator.target_consolidation_balance is None:
            continue

        validators_balances[validator.public_key] = Gwei(
            validator.balance
            + (validator.pending_balance or 0)
            + (validator.target_consolidation_balance or 0)
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

    ``with_consolidations`` fills in ``is_consolidation_source``, ``is_consolidation_target``
    and ``target_consolidation_balance``. The latter is the total balance the target will
    receive from its pending consolidation sources; it stays ``None`` when at least one of
    the sources is not among the fetched validators, i.e. its balance is unknown.
    """
    if not public_keys:
        return []

    chain_head = chain_head or await get_chain_latest_head()
    slot = str(chain_head.slot)
    validators = await fetch_consensus_validators(list(public_keys), slot=slot)

    if with_consolidations:
        _apply_pending_consolidations(
            validators=validators,
            pending_consolidations=await get_pending_consolidations(chain_head, validators),
        )

    if with_pending_deposits:
        validators += await apply_pending_deposits(
            validators=validators,
            public_keys=set(public_keys),
            slot=slot,
            compounding_deposits_only=compounding_deposits_only,
        )

    return validators


def _apply_pending_consolidations(
    validators: list[ConsensusValidator], pending_consolidations: list[PendingConsolidation]
) -> None:
    index_to_validator = {val.index: val for val in validators}

    target_balances: dict[int, Gwei] = defaultdict(lambda: Gwei(0))
    unknown_source_targets: set[int] = set()

    for cons in pending_consolidations:
        source = index_to_validator.get(cons.source_index)
        if source is not None:
            source.is_consolidation_source = True

        target = index_to_validator.get(cons.target_index)
        if target is None:
            continue
        target.is_consolidation_target = True

        if source is None:
            unknown_source_targets.add(cons.target_index)
        else:
            target_balances[cons.target_index] = Gwei(
                target_balances[cons.target_index] + source.balance
            )

    for index, balance in target_balances.items():
        if index not in unknown_source_targets:
            index_to_validator[index].target_consolidation_balance = balance


async def apply_pending_deposits(
    validators: list[ConsensusValidator],
    public_keys: set[HexStr],
    slot: str,
    compounding_deposits_only: bool = False,
) -> list[ConsensusValidator]:
    """
    Fills in ``pending_balance`` of ``validators`` in place and returns the validators that
    are not present in the beacon state yet, but already have pending deposits.
    Can be called separately from `build_consensus_validators` to delay fetching the
    pending deposit queue until it is really needed.
    """
    new_validators: list[ConsensusValidator] = []
    public_key_to_validator = {val.public_key: val for val in validators}

    for deposit in await consensus_client.get_pending_deposits(slot):
        public_key: HexStr = deposit['pubkey']
        if public_key not in public_keys:
            continue

        withdrawal_credentials: HexStr = deposit['withdrawal_credentials']
        if compounding_deposits_only and not withdrawal_credentials.startswith('0x02'):
            continue

        validator = public_key_to_validator.get(public_key)
        if validator is None:
            # Validator is not present in the beacon state yet
            validator = ConsensusValidator(
                index=UNKNOWN_VALIDATOR_INDEX,
                public_key=public_key,
                balance=Gwei(0),
                withdrawal_credentials=withdrawal_credentials,
                status=ValidatorStatus.PENDING_INITIALIZED,
                activation_epoch=settings.network_config.FAR_FUTURE_EPOCH,
            )
            public_key_to_validator[public_key] = validator
            new_validators.append(validator)

        validator.pending_balance = Gwei((validator.pending_balance or 0) + int(deposit['amount']))

    return new_validators


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
