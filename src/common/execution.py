import logging
from urllib.parse import urlparse

from sw_utils import GasManager, InterruptHandler
from web3 import Web3
from web3.types import Wei

from src.common.clients import execution_client
from src.common.metrics import metrics
from src.common.tasks import BaseTask
from src.common.wallet import wallet
from src.config.networks import HOODI
from src.config.settings import settings

logger = logging.getLogger(__name__)

ALCHEMY_DOMAIN = '.alchemy.com'


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


async def check_gas_price(high_priority: bool = False) -> bool:
    gas_manager = build_gas_manager()
    # Alchemy does not support eth_maxPriorityFeePerGas for Hoodi, skip
    if settings.network == HOODI and is_alchemy_used():
        return True

    return await gas_manager.check_gas_price(high_priority)


def build_gas_manager() -> GasManager:
    min_effective_priority_fee_per_gas = settings.network_config.MIN_EFFECTIVE_PRIORITY_FEE_PER_GAS
    return GasManager(
        execution_client=execution_client,
        max_fee_per_gas=Web3.to_wei(settings.max_fee_per_gas_gwei, 'gwei'),
        priority_fee_num_blocks=settings.priority_fee_num_blocks,
        priority_fee_percentile=settings.priority_fee_percentile,
        min_effective_priority_fee_per_gas=min_effective_priority_fee_per_gas,
    )


def is_alchemy_used() -> bool:
    for endpoint in settings.execution_endpoints:
        domain = urlparse(endpoint).netloc
        if domain.lower().endswith(ALCHEMY_DOMAIN):
            return True
    return False


def fake_exponential(factor: int, numerator: int, denominator: int) -> int:
    i = 1
    output = 0
    numerator_accum = factor * denominator
    while numerator_accum > 0:
        output += numerator_accum
        numerator_accum = (numerator_accum * numerator) // (denominator * i)
        i += 1
    return output // denominator
