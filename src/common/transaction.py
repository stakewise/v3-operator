import asyncio
import logging
from math import ceil

from hexbytes import HexBytes
from web3 import Web3
from web3.contract.async_contract import AsyncContractFunction
from web3.types import TxParams, Wei

from src.common.clients import execution_client
from src.common.execution import build_gas_manager
from src.common.wallet import wallet
from src.config.settings import settings

logger = logging.getLogger(__name__)

# geth requires both `maxFeePerGas` and `maxPriorityFeePerGas` to increase by at
# least 10% to replace a pending transaction. Use a bit more for headroom.
REPLACEMENT_GAS_BUMP = 1.125

# how many times to bump the gas when a replacement is rejected as underpriced
REPLACEMENT_ATTEMPTS = 5


class TransactionManager:
    """
    Submits transactions while keeping at most one in-flight transaction per nonce.

    Instead of spending a new nonce while an earlier one is pending, this manager
    re-uses the lowest unconfirmed nonce and bumps its gas price so the new
    transaction *replaces* the stuck one in the mempool. As a bonus the replacing
    transaction carries freshly built calldata, so it does not inherit the stale
    state that doomed the original.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        # nonce -> gas params last broadcast for it, used to size the replacement bump
        self._pending_gas: dict[int, TxParams] = {}

    async def transact(
        self, tx_function: AsyncContractFunction, tx_params: TxParams | None = None
    ) -> HexBytes:
        # serialize submissions so concurrent tasks do not grab the same nonce
        async with self._lock:
            return await self._transact(tx_function, dict(tx_params or {}))  # type: ignore

    async def _transact(self, tx_function: AsyncContractFunction, tx_params: TxParams) -> HexBytes:
        address = wallet.address
        latest_nonce = await execution_client.eth.get_transaction_count(address, 'latest')
        pending_nonce = await execution_client.eth.get_transaction_count(address, 'pending')

        # forget gas records for nonces that have already been mined (nonce
        # `latest_nonce` itself is still pending, so keep it)
        self._pending_gas = {n: p for n, p in self._pending_gas.items() if n >= latest_nonce}

        gas_params = await build_gas_manager().get_high_priority_tx_params()
        max_fee = int(gas_params['maxFeePerGas'])
        priority_fee = int(gas_params['maxPriorityFeePerGas'])

        if pending_nonce > latest_nonce:
            # an earlier transaction is stuck at latest_nonce - replace it instead of
            # queuing a new one behind it
            prev = self._pending_gas.get(latest_nonce)
            if prev is not None:
                max_fee = max(max_fee, _bump(int(prev['maxFeePerGas'])))
                priority_fee = max(priority_fee, _bump(int(prev['maxPriorityFeePerGas'])))
            logger.info(
                'Found pending transaction at nonce %d, replacing it',
                latest_nonce,
            )

        max_fee_cap = Web3.to_wei(settings.max_fee_per_gas_gwei, 'gwei')

        last_error: ValueError | None = None
        for _ in range(REPLACEMENT_ATTEMPTS):
            max_fee, priority_fee = _cap_fees(max_fee, priority_fee, max_fee_cap)
            params: TxParams = {
                **tx_params,
                'nonce': latest_nonce,
                'maxFeePerGas': Wei(max_fee),
                'maxPriorityFeePerGas': Wei(priority_fee),
            }
            try:
                tx_hash = await tx_function.transact(params)
                self._pending_gas[latest_nonce] = params
                return tx_hash
            except ValueError as e:
                if not _is_replacement_underpriced_error(e):
                    raise
                last_error = e
                if max_fee >= max_fee_cap:
                    # cannot bump further without exceeding the configured ceiling
                    logger.warning(
                        'Cannot replace pending transaction at nonce %d: gas price would '
                        'exceed the configured maximum of %s gwei',
                        latest_nonce,
                        settings.max_fee_per_gas_gwei,
                    )
                    break
                max_fee = _bump(max_fee)
                priority_fee = _bump(priority_fee)

        raise last_error  # type: ignore[misc]


def _bump(value: int) -> int:
    return ceil(value * REPLACEMENT_GAS_BUMP)


def _cap_fees(max_fee: int, priority_fee: int, cap: int) -> tuple[int, int]:
    max_fee = min(max_fee, cap)
    # maxPriorityFeePerGas must never exceed maxFeePerGas
    priority_fee = min(priority_fee, max_fee)
    return max_fee, priority_fee


def _is_replacement_underpriced_error(e: ValueError) -> bool:
    message = ''
    if e.args and isinstance(e.args[0], dict):
        message = str(e.args[0].get('message', ''))
    else:
        message = str(e)
    return 'replacement transaction underpriced' in message.lower()


tx_manager = TransactionManager()
