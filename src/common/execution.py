import asyncio
import logging
from urllib.parse import urlparse

from hexbytes import HexBytes
from sw_utils import GasManager, InterruptHandler
from web3 import Web3
from web3.contract.async_contract import AsyncContractFunction
from web3.types import TxParams, Wei

from src.common.clients import execution_client
from src.common.metrics import metrics
from src.common.tasks import BaseTask
from src.common.wallet import wallet
from src.config.networks import HOODI
from src.config.settings import ATTEMPTS_WITH_DEFAULT_GAS, settings

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

    # if wallet_balance < wallet_min_balance:
    #     logger.warning(
    #         'Wallet %s balance is too low. At least %s %s is recommended.',
    #         wallet.address,
    #         Web3.from_wei(wallet_min_balance, 'ether'),
    #         symbol,
    #     )


async def get_wallet_balance() -> Wei:
    return await execution_client.eth.get_balance(wallet.address)


async def transaction_gas_wrapper(
    tx_function: AsyncContractFunction, tx_params: TxParams | None = None
) -> HexBytes:
    """Handles periods with high gas in the network."""
    if not tx_params:
        tx_params = {}

    # trying to submit with basic gas
    attempts_with_default_gas = ATTEMPTS_WITH_DEFAULT_GAS

    # Alchemy does not support eth_maxPriorityFeePerGas for Hoodi
    if settings.network == HOODI and _is_alchemy_used():
        attempts_with_default_gas = 0

    for i in range(attempts_with_default_gas):
        try:
            return await tx_function.transact(tx_params)
        except ValueError as e:
            # Handle only FeeTooLow error
            if not _is_fee_too_low_error(e):
                raise e
            if i < attempts_with_default_gas - 1:  # skip last sleep
                await asyncio.sleep(settings.network_config.SECONDS_PER_BLOCK)

    # use high priority fee
    gas_manager = build_gas_manager()
    tx_params = tx_params | await gas_manager.get_high_priority_tx_params()
    return await tx_function.transact(tx_params)


async def check_gas_price(high_priority: bool = False) -> bool:
    gas_manager = build_gas_manager()
    # Alchemy does not support eth_maxPriorityFeePerGas for Hoodi, skip
    if settings.network == HOODI and _is_alchemy_used():
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


def _is_fee_too_low_error(e: ValueError) -> bool:
    code = None
    if e.args and isinstance(e.args[0], dict):
        code = e.args[0].get('code')
    return code == -32010


def _is_alchemy_used() -> bool:
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
