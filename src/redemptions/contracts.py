from eth_typing import BlockNumber
from web3 import Web3
from web3.types import Wei

from src.common.contracts import ContractWrapper
from src.redemptions.typings import RedeemablePositions


class OsTokenRedeemerContract(ContractWrapper):
    abi_path = 'abi/IOsTokenRedeemer.json'
    settings_key = 'OS_TOKEN_REDEEMER_CONTRACT_ADDRESS'

    async def redeemable_positions(self) -> RedeemablePositions:
        merkle_root, ipfs_hash = await self.contract.functions.redeemablePositions().call()
        return RedeemablePositions(
            merkle_root=Web3.to_hex(merkle_root),
            ipfs_hash=ipfs_hash,
        )

    async def get_exit_queue_cumulative_tickets(self, block_number: BlockNumber) -> int:
        return await self.contract.functions.getExitQueueCumulativeTickets().call(
            block_identifier=block_number
        )

    async def get_exit_queue_missing_assets(self, target_ticket: int) -> Wei:
        return await self.contract.functions.getExitQueueMissingAssets(target_ticket).call()

    async def nonce(self) -> int:
        return await self.contract.functions.nonce().call()


os_token_redeemer_contract = OsTokenRedeemerContract()
