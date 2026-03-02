import logging

from sw_utils import InterruptHandler
from web3 import Web3
from web3.types import Wei

from src.common.clients import execution_client
from src.common.tasks import BaseTask
from src.common.wallet import wallet
from src.config.settings import settings
from src.common.metrics import metrics

logger = logging.getLogger(__name__)


class WalletTask(BaseTask):
    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        await check_wallet_balance()


async def check_wallet_balance() -> None:
    wallet_min_balance = settings.network_config.WALLET_MIN_BALANCE
    symbol = settings.network_config.WALLET_BALANCE_SYMBOL

    if wallet_min_balance <= 0:
        return

    wallet_balance = await get_wallet_balance()
    metrics.wallet_balance.labels(network=settings.network).set(wallet_balance)

    if wallet_balance < wallet_min_balance:
        logger.warning(
            'Wallet %s balance is too low. At least %s %s is recommended.',
            wallet.address,
            Web3.from_wei(wallet_min_balance, 'ether'),
            symbol,
        )


async def get_wallet_balance() -> Wei:
    return await execution_client.eth.get_balance(wallet.address)
