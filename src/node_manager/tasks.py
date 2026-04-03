import logging

from eth_typing import ChecksumAddress
from sw_utils import InterruptHandler
from sw_utils.typings import ProtocolConfig
from web3 import Web3
from web3.types import BlockNumber, Gwei, Wei

from src.common.app_state import AppState
from src.common.contracts import NodesManagerContract, keeper_contract
from src.common.execution import check_gas_price
from src.common.harvest import get_harvest_params
from src.common.protocol_config import get_protocol_config
from src.common.tasks import BaseTask
from src.common.typings import ValidatorType
from src.config.settings import settings
from src.node_manager.execution import (
    fetch_operator_state_from_ipfs,
    submit_state_sync_transaction,
)
from src.node_manager.oracles import poll_eligible_operators, poll_registration_approval
from src.node_manager.register_validators import register_validators
from src.validators.keystores.base import BaseKeystore
from src.validators.tasks import get_deposits_amounts
from src.validators.utils import get_validators_for_registration

logger = logging.getLogger(__name__)


class NodeManagerTask(BaseTask):
    """Periodically polls oracles to check operator eligibility and register validators."""

    def __init__(
        self,
        operator_address: ChecksumAddress,
        keystore: BaseKeystore,
    ) -> None:
        self.operator_address = operator_address
        self.keystore = keystore

    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        if not await check_gas_price(high_priority=True):
            logger.debug('Gas price too high, skipping validators registration')
            return

        protocol_config = await get_protocol_config()

        eligible_amount = await self._get_eligible_amount(protocol_config)
        if eligible_amount is None:
            return

        logger.info(
            'Operator %s is eligible to register/fund %s ETH worth of validators',
            self.operator_address,
            eligible_amount,
        )

        amount_gwei = Gwei(int(Web3.from_wei(eligible_amount, 'gwei')))

        if settings.validator_type == ValidatorType.V1:
            if not settings.disable_validators_registration:
                await self._process_registration(
                    amount=amount_gwei,
                    protocol_config=protocol_config,
                )
            return

        # Fund existing compounding validators first
        if not settings.disable_validators_funding:
            amount_gwei = await self._process_funding(
                amount=amount_gwei,
                operator_address=self.operator_address,
                protocol_config=protocol_config,
            )

        # Register new validators with remaining amount
        if not settings.disable_validators_registration:
            await self._process_registration(
                amount=amount_gwei,
                protocol_config=protocol_config,
            )

    async def _get_eligible_amount(self, protocol_config: ProtocolConfig) -> Wei | None:
        eligible_operators = await poll_eligible_operators(protocol_config)

        for operator in eligible_operators:
            if operator.address == self.operator_address:
                return operator.amount
        return None

    async def _process_registration(
        self,
        amount: Gwei,
        protocol_config: ProtocolConfig,
    ) -> None:
        """Register new validators with the eligible amount."""
        amounts = get_deposits_amounts(amount, settings.validator_type)
        if not amounts:
            logger.info('No remaining amount for new validator registration')
            return

        batch_limit = protocol_config.validators_approval_batch_limit
        amounts = amounts[:batch_limit]

        validators = await get_validators_for_registration(self.keystore, amounts)
        if not validators:
            logger.warning('No available validators for registration')
            return

        request, approval = await poll_registration_approval(
            keystore=self.keystore,
            validators=validators,
            operator_address=self.operator_address,
            protocol_config=protocol_config,
        )

        tx_hash = await register_validators(
            operator_address=self.operator_address,
            approval=approval,
            validators=validators,
            validators_registry_root=request.validators_root,
            validator_index=request.validator_index,
        )

        if tx_hash:
            pub_keys = ', '.join([v.public_key for v in validators])
            logger.info('Registered community vault validators %s: tx=%s', pub_keys, tx_hash)

    async def _process_funding(
        self,
        amount: Gwei,
        operator_address: ChecksumAddress,
        protocol_config: ProtocolConfig,
    ) -> Gwei:
        # linter mock
        logger.info(
            'amount: %s; operator: %s; protocol: %s', amount, operator_address, protocol_config
        )
        return Gwei(amount)


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
