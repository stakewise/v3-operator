from eth_typing import HexStr
from web3 import Web3
from web3.types import BlockNumber, ChecksumAddress, EventData, Wei

from src.common.contracts import ContractWrapper
from src.common.execution import transaction_gas_wrapper
from src.redemptions.typings import OsTokenPosition, RedeemablePositions


class OsTokenRedeemerContract(ContractWrapper):
    abi_path = 'abi/IOsTokenRedeemer.json'
    settings_key = 'OS_TOKEN_REDEEMER_CONTRACT_ADDRESS'

    async def redeemable_positions(
        self, block_number: BlockNumber | None = None
    ) -> RedeemablePositions:
        merkle_root, ipfs_hash = await self.contract.functions.redeemablePositions().call(
            block_identifier=block_number
        )
        return RedeemablePositions(
            merkle_root=Web3.to_hex(merkle_root),
            ipfs_hash=ipfs_hash,
        )

    async def nonce(self, block_number: BlockNumber | None = None) -> int:
        return await self.contract.functions.nonce().call(block_identifier=block_number)

    async def get_exit_queue_cumulative_tickets(
        self, block_number: BlockNumber | None = None
    ) -> int:
        return await self.contract.functions.getExitQueueCumulativeTickets().call(
            block_identifier=block_number
        )

    async def get_exit_queue_missing_assets(
        self, target_ticket: int, block_number: BlockNumber | None = None
    ) -> Wei:
        return await self.contract.functions.getExitQueueMissingAssets(target_ticket).call(
            block_identifier=block_number
        )

    async def positions_manager(self) -> ChecksumAddress:
        return await self.contract.functions.positionsManager().call()

    async def queued_shares(self, block_number: BlockNumber | None = None) -> Wei:
        return await self.contract.functions.queuedShares().call(block_identifier=block_number)

    async def can_process_exit_queue(self, block_number: BlockNumber | None = None) -> bool:
        return await self.contract.functions.canProcessExitQueue().call(
            block_identifier=block_number
        )

    async def get_os_token_positions_redeemed_events(
        self, from_block: BlockNumber, to_block: BlockNumber
    ) -> list[EventData]:
        return await self._get_events(
            event=self.contract.events.OsTokenPositionsRedeemed,  # type: ignore
            from_block=from_block,
            to_block=to_block,
        )

    async def process_exit_queue(self) -> HexStr:
        tx_function = self.contract.functions.processExitQueue()
        tx_hash = await transaction_gas_wrapper(tx_function)
        return Web3.to_hex(tx_hash)

    async def multicall_leaf_to_processed_shares(
        self, positions: list[OsTokenPosition], nonce: int, block_number: BlockNumber
    ) -> list[Wei]:
        calls = [
            self.encode_abi('leafToProcessedShares', [p.leaf_hash(nonce - 1)]) for p in positions
        ]
        results = await self.contract.functions.multicall(calls).call(block_identifier=block_number)
        return [Wei(Web3.to_int(res)) for res in results]


os_token_redeemer_contract = OsTokenRedeemerContract()
