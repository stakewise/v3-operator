from eth_typing import ChecksumAddress
from hexbytes import HexBytes
from sw_utils.tests import faker
from web3.types import Wei

from src.common.typings import ExitRequest
from src.meta_vault.typings import Vault


def create_vault(
    address: ChecksumAddress | None = None,
    is_meta_vault: bool = False,
    sub_vaults_count: int = 0,
    can_harvest: bool = True,
    version: int = 1,
) -> Vault:
    return Vault(
        address=address or faker.eth_address(),
        version=version,
        can_harvest=can_harvest,
        rewards_root=HexBytes(b'\x00' * 32),
        proof_reward=Wei(0),
        proof_unlocked_mev_reward=Wei(0),
        proof=[],
        is_meta_vault=is_meta_vault,
        sub_vaults=[faker.eth_address() for _ in range(sub_vaults_count)],
    )


def create_exit_request(timestamp: int) -> ExitRequest:
    return ExitRequest(
        vault=faker.eth_address(),
        position_ticket=faker.random_int(),
        timestamp=timestamp,
        exit_queue_index=1,
        is_claimed=False,
        is_claimable=False,
        receiver=faker.eth_address(),
        exited_assets=Wei(1),
        total_assets=Wei(1),
    )
