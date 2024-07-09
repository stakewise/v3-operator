from sw_utils.consensus import ValidatorStatus
from web3.types import BlockNumber

from src.common.clients import consensus_client
from src.common.contracts import vault_contract
from src.config.settings import settings
from src.eigenlayer.typings import Validator


async def get_vault_validators(current_block: BlockNumber) -> list[Validator]:
    public_keys = await vault_contract.get_registered_validators_public_keys(
        from_block=settings.network_config.KEEPER_GENESIS_BLOCK,  # vault block
        to_block=current_block,
    )

    results = []
    for i in range(0, len(public_keys), settings.validators_fetch_chunk_size):
        validators = await consensus_client.get_validators_by_ids(
            public_keys[i : i + settings.validators_fetch_chunk_size]
        )
        for beacon_validator in validators['data']:
            # if beacon_validator.get('status') in EXITED_STATUSES:
            # continue

            validator = Validator(
                index=int(beacon_validator['index']),
                public_key=beacon_validator['validator']['pubkey'],
                status=ValidatorStatus(beacon_validator['status']),
                withdrawal_credentials=beacon_validator['validator']['withdrawal_credentials'],
            )
            results.append(validator)

    return results
