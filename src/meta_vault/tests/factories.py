from eth_typing import ChecksumAddress
from hexbytes import HexBytes
from periodic_tasks.common.typings import Vault
from sw_utils.tests import faker


def create_vault(
    address: ChecksumAddress | None = None,
    is_meta_vault: bool = False,
    sub_vaults_count: int = 0,
    can_harvest: bool = True,
) -> Vault:
    return Vault(
        address=address or faker.eth_address(),
        can_harvest=can_harvest,
        rewards_root=HexBytes(b'\x00' * 32),
        proof_reward=0,
        proof_unlocked_mev_reward=0,
        proof=[],
        is_meta_vault=is_meta_vault,
        sub_vaults=[faker.eth_address() for _ in range(sub_vaults_count)],
    )
