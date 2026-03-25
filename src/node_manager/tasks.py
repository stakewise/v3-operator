import logging

from eth_typing import ChecksumAddress
from sw_utils import InterruptHandler
from sw_utils.typings import ProtocolConfig
from web3 import Web3
from web3.types import Gwei

from src.common.execution import check_gas_price
from src.common.protocol_config import get_protocol_config
from src.common.tasks import BaseTask
from src.config.settings import settings
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
        eligible_operators = await poll_eligible_operators(protocol_config)

        for operator in eligible_operators:
            if operator.address != self.operator_address:
                continue

            amount_eth = Web3.from_wei(operator.amount, 'ether')
            logger.info(
                'Operator %s is eligible to register/fund %s ETH worth of validators',
                self.operator_address,
                amount_eth,
            )

            amount_gwei = Gwei(int(Web3.from_wei(operator.amount, 'gwei')))

            # Fund existing compounding validators first
            amount_gwei = await self._process_funding(
                amount=amount_gwei,
                operator_address=self.operator_address,
                protocol_config=protocol_config,
            )

            # Register new validators with remaining amount
            await self._process_registration(
                amount=amount_gwei,
                protocol_config=protocol_config,
            )
            return

        logger.debug('Operator %s is not eligible', self.operator_address)

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
