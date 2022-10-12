from enum import Enum
from typing import Dict, List

import backoff
from aiohttp import ClientSession
from eth_typing import HexStr

from src.config.settings import NETWORK_CONFIG


class ValidatorStatus(Enum):
    """Validator statuses in beacon chain"""

    PENDING_INITIALIZED = "pending_initialized"
    PENDING_QUEUED = "pending_queued"
    ACTIVE_ONGOING = "active_ongoing"
    ACTIVE_EXITING = "active_exiting"
    ACTIVE_SLASHED = "active_slashed"
    EXITED_UNSLASHED = "exited_unslashed"
    EXITED_SLASHED = "exited_slashed"
    WITHDRAWAL_POSSIBLE = "withdrawal_possible"
    WITHDRAWAL_DONE = "withdrawal_done"


PENDING_STATUSES = [ValidatorStatus.PENDING_INITIALIZED, ValidatorStatus.PENDING_QUEUED]


@backoff.on_exception(backoff.expo, Exception, max_time=900)
async def get_finality_checkpoints(
    session: ClientSession, state_id: str = "head"
) -> Dict:
    """Fetches finality checkpoints."""
    endpoint = f"{NETWORK_CONFIG['ETH2_ENDPOINT']}/eth/v1/beacon" \
               f"/states/{state_id}/finality_checkpoints"
    async with session.get(endpoint) as response:
        response.raise_for_status()
        return (await response.json())["data"]


@backoff.on_exception(backoff.expo, Exception, max_time=900)
async def get_validators(
    session: ClientSession,
    public_keys: List[HexStr],
    state_id: str = "head",
) -> List[Dict]:
    """Fetches validators."""
    if not public_keys:
        return []

    _endpoint = NETWORK_CONFIG["ETH2_ENDPOINT"]
    endpoint = f"{_endpoint}/eth/v1/beacon" \
               f"/states/{state_id}/validators?id={'&id='.join(public_keys)}"

    async with session.get(endpoint) as response:
        response.raise_for_status()
        return (await response.json())["data"]


@backoff.on_exception(backoff.expo, Exception, max_time=900)
async def get_validator(
    session: ClientSession,
    public_key: HexStr,
    state_id: str = "head",
) -> List[Dict]:
    """Fetches validators."""
    _endpoint = NETWORK_CONFIG["ETH2_ENDPOINT"]
    endpoint = f"{_endpoint}/eth/v1/beacon/states/{state_id}/validators?id={public_key}"

    async with session.get(endpoint) as response:
        response.raise_for_status()
        return (await response.json())["data"]


@backoff.on_exception(backoff.expo, Exception, max_time=900)
async def get_genesis(session: ClientSession) -> Dict:
    """Fetches beacon chain genesis."""
    endpoint = f"{NETWORK_CONFIG['ETH2_ENDPOINT']}/eth/v1/beacon/genesis"
    async with session.get(endpoint) as response:
        response.raise_for_status()
        return (await response.json())["data"]
