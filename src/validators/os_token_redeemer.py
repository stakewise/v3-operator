import itertools
import logging
from typing import Sequence, cast

from eth_typing import ChecksumAddress, HexStr
from multiproof.standard import standard_leaf_hash
from web3 import Web3
from web3.types import Wei

from src.common.clients import ipfs_fetch_client
from src.common.contracts import multicall_contract, os_token_redeemer_contract

logger = logging.getLogger(__name__)


async def get_vault_to_unprocessed_shares() -> dict[ChecksumAddress, Wei]:
    redeemable_positions = await os_token_redeemer_contract.redeemable_positions()

    # Check whether redeemable positions are available
    if not redeemable_positions.ipfs_hash:
        return {}

    # Fetch redeemable positions data from IPFS
    data = cast(list[dict], await ipfs_fetch_client.fetch_json(redeemable_positions.ipfs_hash))

    # data structure example:
    # [{"owner:" 0x01, "amount": 100000, "vault": 0x02}, ...]

    vault_to_unprocessed_shares: dict[ChecksumAddress, Wei] = {}
    nonce = await os_token_redeemer_contract.nonce()

    # Collect unprocessed leaf shares
    batch_size = 50

    for data_batch in itertools.batched(data, batch_size):
        processed_shares_batch = await _get_processed_shares(nonce, data_batch)

        _update_vault_to_unprocessed_shares(
            vault_to_unprocessed_shares,
            data_batch,
            processed_shares_batch,
        )

    return vault_to_unprocessed_shares


async def _get_processed_shares(nonce: int, data_batch: Sequence[dict]) -> list[Wei]:
    processed_shares_batch: list[tuple[ChecksumAddress, HexStr]] = []

    for data_item in data_batch:
        owner = data_item['owner']
        leaf_shares = data_item['amount']
        vault = data_item['vault']

        # Build leaf
        leaf = standard_leaf_hash(
            values=(nonce, vault, leaf_shares, owner),
            types=['uint256', 'address', 'uint256', 'address'],
        )
        processed_shares_batch.append(
            (
                os_token_redeemer_contract.contract_address,
                os_token_redeemer_contract.encode_abi('leafToProcessedShares', args=[leaf]),
            )
        )

    _, processed_shares = await multicall_contract.aggregate(processed_shares_batch)
    return [Wei(Web3.to_int(share)) for share in processed_shares]


def _update_vault_to_unprocessed_shares(
    vault_to_unprocessed_shares: dict[ChecksumAddress, Wei],
    data_batch: Sequence[dict],
    processed_shares_batch: list[Wei],
) -> None:
    for data_item, processed_shares in zip(data_batch, processed_shares_batch):
        vault = data_item['vault']
        leaf_shares = data_item['amount']

        unprocessed_shares = leaf_shares - processed_shares

        if unprocessed_shares > 0:
            if vault not in vault_to_unprocessed_shares:
                vault_to_unprocessed_shares[vault] = Wei(0)

            vault_to_unprocessed_shares[vault] += unprocessed_shares
