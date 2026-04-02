import logging

from eth_typing import ChecksumAddress
from sw_utils import InterruptHandler
from sw_utils.typings import ProtocolConfig
from web3 import Web3
from web3.types import Gwei, Wei

from src.common.execution import check_gas_price
from src.common.protocol_config import get_protocol_config
from src.common.tasks import BaseTask
from src.common.typings import ValidatorType
from src.config.settings import settings
from src.node_manager.database import OperatorValidatorCrud
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
        """Fund existing compounding validators. Returns remaining eligible amount."""
        compounding_balances = await fetch_compounding_validators_balances()
        if not compounding_balances:
            return amount

        # Filter to only this operator's validators
        operator_keys = OperatorValidatorCrud().get_operator_public_keys()
        compounding_balances = {k: v for k, v in compounding_balances.items() if k in operator_keys}
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
