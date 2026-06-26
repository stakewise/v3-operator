import asyncio
import logging
from math import ceil

from hexbytes import HexBytes
from web3 import Web3
from web3.contract.async_contract import AsyncContractFunction
from web3.exceptions import TimeExhausted
from web3.types import Nonce, TxParams, TxReceipt, Wei

from src.common.clients import execution_client
from src.common.execution import build_gas_manager, is_alchemy_used
from src.common.wallet import wallet
from src.config.networks import HOODI
from src.config.settings import ATTEMPTS_WITH_DEFAULT_GAS, settings

logger = logging.getLogger(__name__)

# geth requires both `maxFeePerGas` and `maxPriorityFeePerGas` to increase by at
# least 10% to replace a pending transaction. Use a bit more for headroom.
REPLACEMENT_GAS_BUMP = 1.125


class Fees:
    """
    Holds EIP-1559 gas fees and keeps two invariants:
    `priority_fee_per_gas <= fee_per_gas` and `fee_per_gas <= max_fee_per_gas`.
    """

    def __init__(
        self, fee_per_gas: int, priority_fee_per_gas: int, max_fee_per_gas: int | None = None
    ) -> None:
        if max_fee_per_gas is None:
            max_fee_per_gas = Web3.to_wei(settings.max_fee_per_gas_gwei, 'gwei')
        self.max_fee_per_gas = max_fee_per_gas
        self.fee_per_gas = fee_per_gas
        self.priority_fee_per_gas = priority_fee_per_gas
        self._cap()

    @staticmethod
    def from_tx_params(tx_params: TxParams, max_fee_per_gas: int | None = None) -> 'Fees':
        return Fees(
            fee_per_gas=int(tx_params['maxFeePerGas']),
            priority_fee_per_gas=int(tx_params['maxPriorityFeePerGas']),
            max_fee_per_gas=max_fee_per_gas,
        )

    def bump(self) -> None:
        self.fee_per_gas = self._bump(self.fee_per_gas)
        self.priority_fee_per_gas = self._bump(self.priority_fee_per_gas)
        self._cap()

    def max_with(self, other: 'Fees') -> 'Fees':
        return Fees(
            fee_per_gas=max(self.fee_per_gas, other.fee_per_gas),
            priority_fee_per_gas=max(self.priority_fee_per_gas, other.priority_fee_per_gas),
            max_fee_per_gas=self.max_fee_per_gas,
        )

    @property
    def tx_params(self) -> TxParams:
        return {
            'maxFeePerGas': Wei(self.fee_per_gas),
            'maxPriorityFeePerGas': Wei(self.priority_fee_per_gas),
        }

    def _cap(self) -> None:
        # never exceed the configured ceiling
        self.fee_per_gas = min(self.fee_per_gas, self.max_fee_per_gas)
        # maxPriorityFeePerGas must never exceed maxFeePerGas
        self.priority_fee_per_gas = min(self.priority_fee_per_gas, self.fee_per_gas)

    @staticmethod
    def _bump(value: int) -> int:
        return ceil(value * REPLACEMENT_GAS_BUMP)


class TransactionManager:
    """
    Submits wallet transactions, keeping at most one in flight at a time.

    The manager owns both submission and receipt-waiting and holds a lock across
    both, so exactly one transaction is in flight for the wallet at any moment. It
    re-uses the lowest unconfirmed nonce: if an earlier transaction is still pending
    (left by a previous task run), the next submission *replaces* it with freshly
    built calldata and bumped fees instead of queuing a new nonce behind the stuck one.

    There is no in-call fee-bump loop. A submission that does not confirm within
    `execution_transaction_timeout` simply stops; the task retries on its next run,
    where the pending transaction is detected and its fees bumped.

    Two gas strategies:
    - `high_priority=True` (e.g. validator registration) skips the default-gas attempts
      and submits high-priority fees straight away.
    - `high_priority=False` first tries the node's default gas, escalating to
      high-priority fees once the default-gas attempts are exhausted.

    Trade-off: while a transaction is being mined the lock blocks other tasks, so no
    two tasks can collide on a nonce. On a receipt timeout the lock is released with
    the transaction still pending, so a different task may replace it on its next run.
    That is harmless.
    """

    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        # nonce -> tx params last broadcast for it, used to size the replacement bump
        self._nonce_to_tx_params: dict[int, TxParams] = {}

    async def transact(
        self,
        tx_function: AsyncContractFunction,
        tx_params: TxParams | None = None,
        high_priority: bool = False,
        estimate_gas: bool = False,
    ) -> TxReceipt | None:
        params: TxParams = dict(tx_params or {})  # type: ignore[assignment]
        # serialize submit + receipt wait so only one wallet tx is in flight at a time
        async with self._lock:
            if estimate_gas:
                # simulate the transaction before submitting it
                await tx_function.estimate_gas(params)
            return await self._transact(tx_function, params, high_priority)

    async def _transact(
        self,
        tx_function: AsyncContractFunction,
        tx_params: TxParams,
        high_priority: bool,
    ) -> TxReceipt | None:
        address = wallet.address
        # Since nonces are 0-indexed, that tx count equals the nonce
        # of the next transaction to be mined.
        latest_nonce = await execution_client.eth.get_transaction_count(address, 'latest')
        pending_nonce = await execution_client.eth.get_transaction_count(address, 'pending')

        # forget gas records for nonces that have already been mined (nonce
        # `latest_nonce` itself may still be pending, so keep it)
        self._nonce_to_tx_params = {
            n: p for n, p in self._nonce_to_tx_params.items() if n >= latest_nonce
        }

        if pending_nonce > latest_nonce:
            # an earlier transaction is stuck at latest_nonce - replace it instead of
            # queuing a new one behind it (skip the default-gas attempts)
            logger.info('Found pending transaction at nonce %d, replacing it', latest_nonce)
            tx_hash = await self._submit_high_priority(tx_function, tx_params, latest_nonce)
        elif high_priority or _skip_default_gas():
            tx_hash = await self._submit_high_priority(tx_function, tx_params, latest_nonce)
        else:
            default_tx_hash = await self._submit_default_gas(tx_function, tx_params, latest_nonce)
            if default_tx_hash is not None:
                tx_hash = default_tx_hash
            else:
                # default gas was not accepted - escalate to high priority fees
                tx_hash = await self._submit_high_priority(tx_function, tx_params, latest_nonce)

        if tx_hash is None:
            # nothing was broadcast (the pending tx is pinned at the fee ceiling)
            return None
        return await self._wait_for_receipt(tx_hash)

    async def _submit_high_priority(
        self,
        tx_function: AsyncContractFunction,
        tx_params: TxParams,
        nonce: Nonce,
    ) -> HexBytes | None:
        gas_params = await build_gas_manager().get_high_priority_tx_params()
        fees = Fees.from_tx_params(gas_params)

        prev = self._nonce_to_tx_params.get(nonce)
        if prev is not None:
            # a transaction we sent for this nonce is still pending - bump from its fees
            prev_fees = Fees.from_tx_params(prev)
            prev_fee_per_gas = prev_fees.fee_per_gas
            prev_fees.bump()
            fees = fees.max_with(prev_fees)
            if fees.fee_per_gas <= prev_fee_per_gas:
                # already at the max_fee_per_gas ceiling - the bump is a no-op, so the node
                # would reject the replacement as underpriced. Leave the pending tx in place;
                # it will mine once the base fee drops.
                logger.warning(
                    'Pending transaction at nonce %d is at the max_fee_per_gas_gwei ceiling '
                    '(%s gwei); cannot bump fees to replace it. Waiting for it to mine or for '
                    'the base fee to drop. Consider raising max_fee_per_gas_gwei.',
                    nonce,
                    settings.max_fee_per_gas_gwei,
                )
                return None

        params: TxParams = {**tx_params, 'nonce': nonce, **fees.tx_params}
        tx_hash = await tx_function.transact(params)
        self._nonce_to_tx_params[nonce] = params
        return tx_hash

    async def _submit_default_gas(
        self,
        tx_function: AsyncContractFunction,
        tx_params: TxParams,
        nonce: Nonce,
    ) -> HexBytes | None:
        # try the node's default gas, waiting a block between FeeTooLow rejections;
        # returns None if every attempt is rejected so the caller can escalate
        params: TxParams = {**tx_params, 'nonce': nonce}
        for i in range(ATTEMPTS_WITH_DEFAULT_GAS):
            try:
                return await tx_function.transact(params)
            except ValueError as e:
                if not _is_fee_too_low_error(e):
                    raise
                if i < ATTEMPTS_WITH_DEFAULT_GAS - 1:  # skip the last sleep
                    await asyncio.sleep(settings.network_config.SECONDS_PER_BLOCK)

        return None

    @staticmethod
    async def _wait_for_receipt(tx_hash: HexBytes) -> TxReceipt | None:
        logger.info('Waiting for transaction %s confirmation', Web3.to_hex(tx_hash))
        try:
            tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
                tx_hash, timeout=settings.execution_transaction_timeout
            )
        except TimeExhausted:
            logger.info(
                'Transaction %s is still pending, will replace it on the next run',
                Web3.to_hex(tx_hash),
            )
            return None
        if not tx_receipt['status']:
            return None
        return tx_receipt


def _skip_default_gas() -> bool:
    # Alchemy does not support eth_maxPriorityFeePerGas for Hoodi, go straight to high priority
    return settings.network == HOODI and is_alchemy_used()


def _is_fee_too_low_error(e: ValueError) -> bool:
    code = None
    if e.args and isinstance(e.args[0], dict):
        code = e.args[0].get('code')
    return code == -32010


tx_manager = TransactionManager()
