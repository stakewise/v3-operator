import logging

from eth_typing import ChecksumAddress, HexStr
from eth_utils import add_0x_prefix
from sw_utils import ValidatorStatus, chunkify
from sw_utils.consensus import EXITED_STATUSES
from web3.types import Gwei

from src.common.clients import consensus_client, execution_client
from src.common.contracts import VaultContract
from src.config.settings import settings
from src.validators.typings import ConsensusValidator

EXITING_STATUSES = [ValidatorStatus.ACTIVE_EXITING] + EXITED_STATUSES

logger = logging.getLogger(__name__)


async def fetch_post_pectra_validators(
    vault_address: ChecksumAddress,
) -> list[ConsensusValidator]:
    vault_contract = VaultContract(vault_address)
    current_block = await execution_client.eth.get_block_number()
    public_keys = await vault_contract.get_registered_post_pectra_validators_public_keys(
        from_block=settings.network_config.KEEPER_GENESIS_BLOCK,
        to_block=current_block,
    )
    return await _fetch_non_exiting_consensus_validators(public_keys)


async def _fetch_non_exiting_consensus_validators(
    public_keys: list[HexStr],
) -> list[ConsensusValidator]:
    validators = []
    for chunk_keys in chunkify(public_keys, settings.validators_fetch_chunk_size):
        beacon_validators = await consensus_client.get_validators_by_ids(chunk_keys)
        for beacon_validator in beacon_validators['data']:
            status = ValidatorStatus(beacon_validator['status'])
            if status in EXITING_STATUSES:
                continue

            public_key = add_0x_prefix(beacon_validator['validator']['pubkey'])
            validators.append(
                ConsensusValidator(
                    public_key=public_key,
                    index=int(beacon_validator['index']),
                    balance=Gwei(int(beacon_validator['balance'])),
                    withdrawal_credentials=beacon_validator['validator']['withdrawal_credentials'],
                    status=status,
                )
            )

    return validators
