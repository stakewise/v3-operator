import logging

from eth_typing import ChecksumAddress
from sw_utils import EventScanner, InterruptHandler
from sw_utils.typings import ProtocolConfig
from web3 import Web3
from web3.types import Gwei, Wei

from src.common.consensus import get_chain_finalized_head
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
from src.node_manager.oracles import (
    poll_eligible_operators,
    poll_funding_approval,
    poll_registration_approval,
)
from src.node_manager.register_validators import fund_validators, register_validators
from src.validators.consensus import fetch_compounding_validators_balances
from src.validators.keystores.base import BaseKeystore
from src.validators.tasks import get_deposits_amounts, get_funding_amounts
from src.validators.utils import get_validators_for_registration

logger = logging.getLogger(__name__)


class NodeManagerTask(BaseTask):
    """Periodically polls oracles to check operator eligibility and register validators."""

    def __init__(
        self,
        operator_address: ChecksumAddress,
        keystore: BaseKeystore,
        validators_scanner: EventScanner,
    ) -> None:
        self.operator_address = operator_address
        self.keystore = keystore
        self.validators_scanner = validators_scanner

    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        chain_head = await get_chain_finalized_head()
        await self.validators_scanner.process_new_events(chain_head.block_number)

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
        amounts = get_deposits_amounts(amount, ValidatorType.V2)
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
        """Fund existing compounding validators. Returns remaining eligible amount."""
        compounding_balances = await fetch_compounding_validators_balances()
        if not compounding_balances:
            return amount

        validator_fundings = get_funding_amounts(compounding_balances, amount)
        if not validator_fundings:
            return amount

        funded_total = Gwei(0)
        batch_limit = protocol_config.validators_approval_batch_limit

        # Process in batches
        funding_items = list(validator_fundings.items())
        for i in range(0, len(funding_items), batch_limit):
            batch = dict(funding_items[i : i + batch_limit])

            signatures = await poll_funding_approval(
                validator_fundings=batch,
                operator_address=operator_address,
                protocol_config=protocol_config,
            )

            tx_hash = await fund_validators(
                operator_address=self.operator_address,
                signatures=signatures,
                validator_fundings=batch,
            )

            if tx_hash:
                batch_total = sum(batch.values())
                funded_total = Gwei(funded_total + batch_total)
                pub_keys = ', '.join(batch.keys())
                logger.info('Funded community vault validators %s: tx=%s', pub_keys, tx_hash)
            else:
                logger.warning('Community vault funding batch failed, stopping funding')
                break

        return Gwei(amount - funded_total)


class StateSyncTask(BaseTask):
    """Periodically syncs operator state after global state updates."""

    def __init__(self, operator_address: ChecksumAddress) -> None:
        self.operator_address = operator_address

    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        node_manager_contract = NodesManagerContract()
        chain_head = await get_chain_finalized_head()
        block_number = chain_head.block_number

        # 1. Get current state nonce and check if operator already synced
        current_nonce = await node_manager_contract.get_state_nonce(block_number)

        operator_nonce = await node_manager_contract.get_operator_last_state_nonce(
            self.operator_address, block_number=block_number
        )
        if operator_nonce == current_nonce:
            logger.debug('Operator %s state already synced', self.operator_address)
            return

        # 2. Find the StateUpdated event to get IPFS hash
        event = await node_manager_contract.get_last_state_updated_event(
            from_block=settings.network_config.NODES_MANAGER_GENESIS_BLOCK,
            to_block=block_number,
        )
        if not event:
            return

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
            harvest_params = await get_harvest_params(settings.vault)
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
