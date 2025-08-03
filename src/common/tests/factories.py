import random

from eth_typing import BlockNumber
from sw_utils import ChainHead
from web3.types import Timestamp

from src.config.networks import HOODI, NETWORKS
from src.config.settings import settings


def create_chain_head(
    epoch: int | None = None,
    block_number: int | None = None,
    slot: int | None = None,
    execution_ts: int | None = None,
) -> ChainHead:
    if epoch is None:
        epoch = random.randint(1, 10000)

    if slot is None:
        if settings.network_config:
            slot = epoch * settings.network_config.SLOTS_PER_EPOCH + 1
        else:
            # Fallback for tests without network_config
            slot = epoch * NETWORKS[HOODI].SLOTS_PER_EPOCH + 1

    if block_number is None:
        block_number = int(slot * 0.9)

    if execution_ts is None:
        if settings.network_config:
            execution_ts = (
                settings.network_config.GENESIS_TIMESTAMP
                + slot * settings.network_config.SLOTS_PER_EPOCH
            )
        else:
            # Fallback for tests without network_config
            execution_ts = (
                NETWORKS[HOODI].GENESIS_TIMESTAMP + slot * NETWORKS[HOODI].SLOTS_PER_EPOCH
            )

    return ChainHead(
        epoch=epoch,
        block_number=BlockNumber(block_number),
        slot=slot,
        execution_ts=Timestamp(execution_ts),
    )
