import logging

from eth_typing import ChecksumAddress
from sw_utils import InterruptHandler
from web3 import Web3
from web3.types import BlockNumber

from src.common.app_state import AppState
from src.common.contracts import NodesManagerContract, keeper_contract
from src.common.execution import check_gas_price
from src.common.harvest import get_harvest_params
from src.common.protocol_config import get_protocol_config
from src.common.tasks import BaseTask
from src.config.settings import settings
from src.node_manager.execution import (
    fetch_operator_state_from_ipfs,
    submit_state_sync_transaction,
)
from src.node_manager.oracles import poll_eligible_operators

logger = logging.getLogger(__name__)


class NodeManagerTask(BaseTask):
    """Periodically polls oracles to check operator eligibility."""

    def __init__(self, withdrawals_address: ChecksumAddress) -> None:
        self.withdrawals_address = withdrawals_address

    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        protocol_config = await get_protocol_config()
        eligible_operators = await poll_eligible_operators(protocol_config)

        for operator in eligible_operators:
            if operator.address == self.withdrawals_address:
                amount_eth = Web3.from_wei(operator.amount, 'ether')
                logger.info(
                    'Operator %s is eligible to register/fund %s ETH worth of validators',
                    self.withdrawals_address,
                    amount_eth,
                )
                return

        logger.debug('Operator %s is not eligible', self.withdrawals_address)


class StateSyncTask(BaseTask):
    """Periodically syncs operator state after global state updates."""

    def __init__(self, operator_address: ChecksumAddress) -> None:
        self.operator_address = operator_address

    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        nm_contract = NodesManagerContract()
        app_state = AppState()

        # 1. Get current state nonce and check if operator already synced
        state_data = await nm_contract.get_state_data()
        current_nonce = state_data[3]

        operator_nonce = await nm_contract.get_operator_last_state_nonce(self.operator_address)
        if operator_nonce == current_nonce:
            logger.debug('Operator %s state already synced', self.operator_address)
            return

        # 2. Find the StateUpdated event to get IPFS hash
        from_block = app_state.state_sync_block or settings.network_config.KEEPER_GENESIS_BLOCK
        to_block = await nm_contract.execution_client.eth.get_block_number()
        event = await nm_contract.get_last_state_updated_event(
            from_block=BlockNumber(from_block),
            to_block=BlockNumber(to_block),
        )
        if not event:
            logger.debug('No StateUpdated event found')
            return

        # Update checkpoint
        app_state.state_sync_block = BlockNumber(event['blockNumber'])

        ipfs_hash: str = event['args']['stateIpfsHash']

        # 3. Fetch operator state from IPFS
        operator_params = await fetch_operator_state_from_ipfs(ipfs_hash, self.operator_address)
        if not operator_params:
            logger.warning('Operator %s not found in state IPFS data', self.operator_address)
            return

        # 4. Check gas price
        if not await check_gas_price():
            logger.debug('Gas price too high, skipping state sync')
            return

        # 5. Check if vault needs harvesting, get harvest params if so
        harvest_params = None
        if await keeper_contract.can_harvest(settings.vault):
            harvest_params = await get_harvest_params()
            if harvest_params is None:
                logger.warning('Vault requires harvesting but failed to fetch harvest params')
                return

        # 6. Submit transaction
        tx_hash = await submit_state_sync_transaction(
            operator_address=self.operator_address,
            params=operator_params,
            harvest_params=harvest_params,
        )
        if tx_hash:
            logger.info('State sync successful: %s', tx_hash)
