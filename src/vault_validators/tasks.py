from sw_utils import InterruptHandler
from web3 import Web3

from src.common.checks import wait_execution_catch_up_consensus
from src.common.clients import ipfs_fetch_client
from src.common.consensus import get_chain_finalized_head
from src.common.contracts import keeper_contract
from src.common.tasks import BaseTask

import logging

from src.config.settings import settings
from src.vault_validators.typings import VaultValidator

logger = logging.getLogger(__name__)


class NewValidatorsTask(BaseTask):
    name = 'src.apps.validators.tasks.NewValidatorsTask'
    genesis_block = settings.NETWORK_CONFIG.VAULTS_REGISTRY_GENESIS_BLOCK

    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        chain_state = await get_chain_finalized_head()
        await wait_execution_catch_up_consensus(
            chain_state=chain_state, interrupt_handler=interrupt_handler
        )
        from_block = self._get_from_block()
        to_block = chain_state.execution_block
        if not to_block:
            return
        logger.debug('Syncing new validators. From block %s to block %s', from_block, to_block)

        events = await keeper_contract.get_validators_approval_events(
            from_block=from_block, to_block=to_block, vault=settings.vault
        )
        vault_validators: list[VaultValidator] = []

        for event in events:
            ipfs_hash = event['args']['exitSignaturesIpfsHash']
            block_number = event['blockNumber']

            ipfs_data = await ipfs_fetch_client.fetch_bytes(ipfs_hash)
            public_keys = parse_exit_signature(ipfs_data).public_keys
            for public_key in public_keys:
                vault_validators.append(
                    VaultValidator(
                        block_number=block_number,
                        public_key=public_key,
                    )
                )

        await VaultValidatorCrud.add_vault_validators(vault_validators)
        await self.update_checkpoint(to_block)
