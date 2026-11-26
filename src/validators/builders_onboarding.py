"""
Keeps network validators exact across the builders onboarding at the Glamsterdam fork.

Before the fork, a deposit with builder withdrawal credentials (0xB0) takes a validator index
only if the consensus layer processes it before the fork. If it is still pending at the fork,
it is onboarded as a builder instead, see `onboard_builders_from_pending_deposits`
in the Gloas fork spec. Until then, the index of every validator queued after it is unknown.

- Before the fork, valid 0xB0 deposits are saved as builder deposits
  instead of network validators, see `process_network_validator_events`.
  Validator approvals are blocked from the first builder deposit.
- At the fork, builder deposits that became validators are moved to network validators,
  the rest are dropped. Network validators saved by operator versions without
  the builder deposits filter may contain builders onboarded at the fork, those are removed.
  Then validator approvals are enabled again.

Removing the onboarded builders needs the beacon state of the fork slot, which a checkpoint-synced
consensus node may not have. Network validators scanned with the builder deposits filter
from the start contain no such builders, they are marked with the filter marker,
see `mark_fresh_network_validators`. If the fork state is unavailable:
- with the marker, nothing is removed;
- without the marker, the network validators are dropped and rescanned from genesis
  with the filter, which gives the same result. An archive consensus endpoint avoids the rescan.
"""

import logging
from collections.abc import Iterator
from contextlib import contextmanager

from aiohttp import ClientResponseError
from eth_typing import BlockNumber, BLSPubkey, BLSSignature, HexStr
from eth_utils import add_0x_prefix
from sw_utils import is_valid_deposit_data_signature
from sw_utils.typings import Bytes32, ChainHead
from web3 import Web3
from web3.types import Gwei

from src.common.clients import consensus_client
from src.common.consensus import get_chain_epoch_head
from src.common.contracts import validators_registry_contract
from src.common.utils import calc_slot_by_block_timestamp, get_current_timestamp
from src.config.settings import settings
from src.validators.consensus import fetch_consensus_validators
from src.validators.database import (
    BuilderDepositCrud,
    CheckpointCrud,
    NetworkValidatorCrud,
    transaction,
)
from src.validators.event_processors import (
    get_latest_deposits,
    process_network_validator_event,
    scan_validators_events,
)
from src.validators.ipfs_dumps import load_genesis_validators
from src.validators.typings import NetworkValidator

BUILDER_DEPOSITS_FILTER_APPLIED = 1

logger = logging.getLogger(__name__)


class _ForkStateUnavailableError(Exception):
    """The consensus node has no beacon state of the Glamsterdam fork slot."""


def mark_fresh_network_validators() -> None:
    """
    Sets the builder deposits filter marker if the network validators table is empty.
    Call it before the network validators are loaded or scanned.
    """
    checkpoint_crud = CheckpointCrud()
    if (
        checkpoint_crud.get_checkpoint(checkpoint_crud.CHECKPOINT_BUILDER_DEPOSITS_FILTER)
        is not None
    ):
        return
    if NetworkValidatorCrud().get_last_network_validator() is not None:
        return
    checkpoint_crud.update_checkpoint(
        checkpoint_crud.CHECKPOINT_BUILDER_DEPOSITS_FILTER, BUILDER_DEPOSITS_FILTER_APPLIED
    )


async def resolve_builders_onboarding(chain_head: ChainHead) -> None:
    """
    Runs once, when the chain head reaches the Glamsterdam fork
    and network validators are scanned to the chain head.
    """
    network_config = settings.network_config
    if chain_head.slot < network_config.GLAMSTERDAM_SLOT:
        return

    checkpoint_crud = CheckpointCrud()
    if checkpoint_crud.get_checkpoint(checkpoint_crud.CHECKPOINT_BUILDERS_ONBOARDING) is not None:
        return

    # All deposit events up to the chain head must be in network validators
    network_validators_block = checkpoint_crud.get_checkpoint(
        checkpoint_crud.CHECKPOINT_NETWORK_VALIDATORS
    )
    if network_validators_block is None or network_validators_block < chain_head.block_number:
        logger.info('Waiting for network validators to be scanned to the chain head')
        return

    removed: list[HexStr] = []
    try:
        removed = await _get_onboarded_builders(
            chain_head=chain_head, to_block=BlockNumber(network_validators_block)
        )
    except _ForkStateUnavailableError as e:
        filter_marker = checkpoint_crud.get_checkpoint(
            checkpoint_crud.CHECKPOINT_BUILDER_DEPOSITS_FILTER
        )
        if filter_marker is not None:
            logger.warning(
                'Skipping removal of the builders onboarded at the Glamsterdam fork: %s. '
                'Network validators were scanned with the builder deposits filter.',
                e,
            )
        else:
            logger.warning(
                'The consensus node has no beacon state of the Glamsterdam fork (%s), '
                'so the builders onboarded at the fork cannot be removed from network validators. '
                'Rescanning network validators from genesis with the builder deposits filter, '
                'this takes a while. Use an archive consensus endpoint to avoid the rescan.',
                e,
            )
            await _rescan_network_validators(chain_head)

    added = await _get_builder_deposit_validators(chain_head)

    with transaction() as connection:
        network_validator_crud = NetworkValidatorCrud(connection)
        network_validator_crud.save_network_validators(added)
        network_validator_crud.delete_network_validators(removed)
        BuilderDepositCrud(connection).delete_all_builder_deposits()
        CheckpointCrud(connection).update_checkpoint(
            CheckpointCrud.CHECKPOINT_BUILDERS_ONBOARDING, network_config.GLAMSTERDAM_EPOCH
        )

    logger.info(
        'Resolved builders onboarding, added %d network validator(s): %s, '
        'removed %d network validator(s): %s. Validator approvals are enabled.',
        len(added),
        [v.public_key for v in added],
        len(removed),
        removed,
    )


async def get_validators_start_index() -> int | None:
    """
    The index for the next validator, `None` while the index is unknown:
    approvals are blocked, or there are builder deposits not yet saved by the scanner.
    """
    latest_public_keys, latest_builder_deposits = await get_latest_deposits()
    if latest_builder_deposits or is_validator_approvals_blocked():
        logger.warning(
            'The next validator index is unknown '
            'until the builders onboarding at the Glamsterdam fork is resolved.'
        )
        return None
    return NetworkValidatorCrud().get_next_validator_index(list(latest_public_keys))


def is_validator_approvals_blocked() -> bool:
    """
    Blocked from the first builder deposit until the fork is resolved,
    and after the fork until it is resolved.
    Builder deposits not yet saved by the scanner are not taken into account.
    """
    if BuilderDepositCrud().has_builder_deposits():
        return True

    current_slot = calc_slot_by_block_timestamp(get_current_timestamp())
    if current_slot < settings.network_config.GLAMSTERDAM_SLOT:
        return False

    checkpoint_crud = CheckpointCrud()
    return checkpoint_crud.get_checkpoint(checkpoint_crud.CHECKPOINT_BUILDERS_ONBOARDING) is None


async def _get_builder_deposit_validators(chain_head: ChainHead) -> list[NetworkValidator]:
    """Builder deposits processed by the consensus layer as validators before the fork."""
    builder_deposits = BuilderDepositCrud().get_builder_deposits()
    if not builder_deposits:
        return []

    validators = await fetch_consensus_validators(
        [d.public_key for d in builder_deposits], slot=str(chain_head.slot)
    )
    validator_public_keys = {v.public_key for v in validators}
    return [
        NetworkValidator(public_key=d.public_key, block_number=d.block_number)
        for d in builder_deposits
        if d.public_key in validator_public_keys
    ]


async def _get_onboarded_builders(chain_head: ChainHead, to_block: BlockNumber) -> list[HexStr]:
    """
    Network validators onboarded as builders at the fork that never become validators.
    A public key can be deposited both as a builder and as a validator.
    """
    fork_state_id = str(settings.network_config.GLAMSTERDAM_SLOT)

    with _fork_state_access():
        builders = await consensus_client.get_builders(state_id=fork_state_id)
    public_keys = NetworkValidatorCrud().get_registered_public_keys(
        [add_0x_prefix(b['builder']['pubkey']) for b in builders]
    )
    if not public_keys:
        return []

    validators = await fetch_consensus_validators(list(public_keys), slot=str(chain_head.slot))
    public_keys -= {v.public_key for v in validators}
    if not public_keys:
        return []

    with _fork_state_access():
        pending_deposits = await consensus_client.get_pending_deposits(fork_state_id)
    public_keys -= _get_valid_pending_deposit_public_keys(pending_deposits, public_keys)
    if not public_keys:
        return []

    events = await validators_registry_contract.get_deposit_events(
        from_block=await _get_glamsterdam_first_block_number(), to_block=to_block
    )
    for event in events:
        validator = process_network_validator_event(
            event, settings.network_config.GENESIS_FORK_VERSION
        )
        if validator:
            public_keys.discard(validator.public_key)

    return sorted(public_keys)


def _get_valid_pending_deposit_public_keys(
    pending_deposits: list[dict], public_keys: set[HexStr]
) -> set[HexStr]:
    """Public keys from the set that have a pending deposit with a valid signature."""
    result: set[HexStr] = set()
    for deposit in pending_deposits:
        public_key = add_0x_prefix(deposit['pubkey'])
        if public_key not in public_keys or public_key in result:
            continue
        if is_valid_deposit_data_signature(
            BLSPubkey(Web3.to_bytes(hexstr=public_key)),
            Bytes32(Web3.to_bytes(hexstr=deposit['withdrawal_credentials'])),
            BLSSignature(Web3.to_bytes(hexstr=deposit['signature'])),
            Gwei(int(deposit['amount'])),
            settings.network_config.GENESIS_FORK_VERSION,
        ):
            result.add(public_key)
    return result


async def _get_glamsterdam_first_block_number() -> BlockNumber:
    """
    The first execution block processed by Glamsterdam rules:
    the one after the payload of the last pre-fork beacon block.
    """
    head = await get_chain_epoch_head(settings.network_config.GLAMSTERDAM_EPOCH)
    return BlockNumber(head.block_number + 1)


async def _rescan_network_validators(chain_head: ChainHead) -> None:
    """Drops network validators with their scan state and loads them again with the filter."""
    with transaction() as connection:
        NetworkValidatorCrud(connection).delete_all_network_validators()
        BuilderDepositCrud(connection).delete_all_builder_deposits()
        checkpoint_crud = CheckpointCrud(connection)
        checkpoint_crud.delete_checkpoint(checkpoint_crud.CHECKPOINT_NETWORK_VALIDATORS)
        checkpoint_crud.update_checkpoint(
            checkpoint_crud.CHECKPOINT_BUILDER_DEPOSITS_FILTER, BUILDER_DEPOSITS_FILTER_APPLIED
        )

    await load_genesis_validators()
    await scan_validators_events(chain_head.block_number, is_startup=True)


@contextmanager
def _fork_state_access() -> Iterator[None]:
    """
    Clients answer differently for a pruned state (404, 400, 500), 5xx are retried by sw-utils.
    Other errors, like timeouts, are not about the state and propagate.
    """
    try:
        yield
    except ClientResponseError as e:
        raise _ForkStateUnavailableError(f'HTTP {e.status}') from e
