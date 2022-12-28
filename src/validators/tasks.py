import logging

import backoff
from eth_typing import HexStr
from web3 import Web3
from web3.types import Wei

from src.common.utils import MGNO_RATE, WAD
from src.config.networks import GNOSIS
from src.config.settings import (
    APPROVAL_MAX_VALIDATORS,
    DEPOSIT_AMOUNT,
    NETWORK,
    VAULT_CONTRACT_ADDRESS,
)
from src.validators.consensus import get_consensus_fork
from src.validators.database import get_next_validator_index
from src.validators.execution import (
    get_available_assets,
    get_available_deposit_data,
    get_latest_network_validator_public_keys,
    get_oracles,
    get_validators_registry_root,
    register_multiple_validator,
    register_single_validator,
)
from src.validators.signing import get_exit_signature_shards
from src.validators.typings import (
    ApprovalRequest,
    BLSPrivkey,
    DepositData,
    OraclesApproval,
)
from src.validators.utils import send_approval_requests

logger = logging.getLogger(__name__)


async def register_validators(private_keys: dict[HexStr, BLSPrivkey]) -> None:
    """Registers vault validators."""
    vault_balance = await get_available_assets()
    if NETWORK == GNOSIS:
        # apply GNO -> mGNO exchange rate
        vault_balance = Wei(int(vault_balance * MGNO_RATE // WAD))

    # calculate number of validators that can be registered
    validators_count: int = min(
        APPROVAL_MAX_VALIDATORS, vault_balance // DEPOSIT_AMOUNT
    )
    if not validators_count:
        # not enough balance to register validators
        return

    deposit_data, deposit_data_tree = await get_available_deposit_data(
        private_keys=private_keys,
        validators_count=validators_count
    )
    if not (deposit_data and deposit_data_tree):
        return

    oracles_approval = await get_oracles_approval(private_keys, deposit_data)
    if len(deposit_data) == 1:
        return await register_single_validator(deposit_data_tree, deposit_data[0], oracles_approval)

    if len(deposit_data) > 1:
        return await register_multiple_validator(deposit_data_tree, deposit_data, oracles_approval)


@backoff.on_exception(backoff.expo, Exception, max_tries=10)
async def get_oracles_approval(
    private_keys: dict[HexStr, BLSPrivkey],
    deposit_data: list[DepositData]
) -> OraclesApproval:
    """Updates vote for the new rewards."""
    # get latest oracles
    oracles = await get_oracles()

    # get latest registry root
    registry_root = await get_validators_registry_root()

    # get next validator index for exit signature
    latest_public_keys = await get_latest_network_validator_public_keys()
    validator_index = get_next_validator_index(list(latest_public_keys))

    # fetch current fork data
    fork = await get_consensus_fork()

    # get exit signature shards
    request = ApprovalRequest(
        validator_index=validator_index,
        vault_address=VAULT_CONTRACT_ADDRESS,
        validators_root=Web3.to_hex(registry_root),
        public_keys=[],
        deposit_signatures=[],
        public_key_shards=[],
        exit_signature_shards=[]
    )
    for deposit in deposit_data:
        shards = get_exit_signature_shards(
            validator_index=validator_index,
            private_key=private_keys[deposit.public_key],
            oracles=oracles,
            fork=fork
        )
        if not shards:
            break

        request.public_keys.append(deposit.public_key)
        request.deposit_signatures.append(deposit.signature)
        request.public_key_shards.append(shards.public_keys)
        request.exit_signature_shards.append(shards.exit_signatures)

    # send approval request to oracles
    signatures, ipfs_hash = await send_approval_requests(oracles, request)
    return OraclesApproval(
        signatures=signatures,
        ipfs_hash=ipfs_hash,
        validators_registry_root=registry_root,
    )
