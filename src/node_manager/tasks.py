import logging

from eth_typing import ChecksumAddress
from sw_utils import InterruptHandler
from web3 import Web3

from src.common.protocol_config import get_protocol_config
from src.common.tasks import BaseTask
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
