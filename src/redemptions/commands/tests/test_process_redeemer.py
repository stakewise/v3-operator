import asyncio
from contextlib import contextmanager
from typing import Iterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_typing import BlockNumber, ChecksumAddress
from hexbytes import HexBytes
from sw_utils.tests import faker
from web3 import Web3
from web3.exceptions import Web3Exception
from web3.types import Gwei, Wei

from src.redemptions.commands.process_redeemer import (
    _build_multi_proof,
    _process_exit_queue,
    _startup_check,
    _submit_redeem_position,
    process,
    redeem_positions,
)
from src.redemptions.os_token_converter import OsTokenConverter
from src.redemptions.typings import OsTokenPosition

MODULE = 'src.redemptions.commands.process_redeemer'

VAULT_1 = Web3.to_checksum_address('0x' + '11' * 20)
VAULT_2 = Web3.to_checksum_address('0x' + '22' * 20)
OWNER_1 = Web3.to_checksum_address('0x' + '33' * 20)
OWNER_2 = Web3.to_checksum_address('0x' + '44' * 20)


# --- Pure function tests (no mocks) ---


class TestBuildMultiProof:
    def test_single_position(self) -> None:
        position = make_position(leaf_shares=1000, processed_shares=500)
        result = _build_multi_proof(
            nonce=5,
            all_positions=[position],
            positions_to_redeem=[position],
        )
        assert len(result.leaves) == 1

    def test_partial_redeem(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, leaf_shares=1000, processed_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, leaf_shares=2000, processed_shares=1000)

        result = _build_multi_proof(
            nonce=5,
            all_positions=[pos1, pos2],
            positions_to_redeem=[pos1],
        )
        assert len(result.leaves) == 1
        assert len(result.proof) > 0

    def test_all_positions_redeemed(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, leaf_shares=1000, processed_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, leaf_shares=2000, processed_shares=1000)

        result = _build_multi_proof(
            nonce=5,
            all_positions=[pos1, pos2],
            positions_to_redeem=[pos1, pos2],
        )
        assert len(result.leaves) == 2


class TestRedeemPositions:
    async def test_empty_positions(self) -> None:
        with _mock_redeem_positions() as mocks:
            await redeem_positions(
                all_positions=[],
                os_token_positions=[],
                converter=make_converter(),
                nonce=5,
                block_number=BlockNumber(100),
            )
        mocks['submit_mock'].assert_not_called()

    async def test_single_position_sufficient_assets(self) -> None:
        position = make_position(processed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(1000)) as mocks:
            await redeem_positions(
                all_positions=[position],
                os_token_positions=[position],
                converter=make_converter(),
                nonce=5,
                block_number=BlockNumber(100),
            )

        assert mocks['submit_mock'].await_count == 1
        assert _submitted_position(mocks).shares_to_redeem == Wei(500)

    async def test_single_position_insufficient_assets_partial_fill(self) -> None:
        position = make_position(processed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(100)) as mocks:
            await redeem_positions(
                all_positions=[position],
                os_token_positions=[position],
                converter=make_converter(100, 100),
                nonce=5,
                block_number=BlockNumber(100),
            )

        assert mocks['submit_mock'].await_count == 1
        assert _submitted_position(mocks).shares_to_redeem == Wei(100)

    async def test_single_position_zero_withdrawable_skipped(self) -> None:
        position = make_position(processed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(0)) as mocks:
            await redeem_positions(
                all_positions=[position],
                os_token_positions=[position],
                converter=make_converter(100, 100),
                nonce=5,
                block_number=BlockNumber(100),
            )

        mocks['submit_mock'].assert_not_called()

    async def test_multiple_positions_share_vault_cache(self) -> None:
        """Withdrawable is fetched once per vault, decremented after each redemption."""
        pos1 = make_position(owner=OWNER_1, processed_shares=500)
        pos2 = make_position(owner=OWNER_2, processed_shares=0)

        get_withdrawable = AsyncMock(return_value=Wei(700))
        with _mock_redeem_positions(withdrawable=get_withdrawable) as mocks:
            await redeem_positions(
                all_positions=[pos1, pos2],
                os_token_positions=[pos1, pos2],
                converter=make_converter(100, 100),
                nonce=5,
                block_number=BlockNumber(100),
            )

        # Two redemption transactions (one per position)
        assert mocks['submit_mock'].await_count == 2
        # Single fetch — second position uses cached value
        assert get_withdrawable.await_count == 1

        first_position = _submitted_position(mocks, 0)
        second_position = _submitted_position(mocks, 1)
        assert first_position.owner == OWNER_1 and first_position.shares_to_redeem == Wei(500)
        assert second_position.owner == OWNER_2 and second_position.shares_to_redeem == Wei(200)

    async def test_pre_capped_shares_to_redeem_submitted_not_unprocessed(self) -> None:
        """assign_shares_to_redeem may cap shares_to_redeem below unprocessed_shares.
        redeem_positions must submit the pre-capped value, not re-derive from unprocessed_shares."""
        # unprocessed_shares = 1000, but budget was exhausted mid-position
        pos = make_position(leaf_shares=1000, processed_shares=0, shares_to_redeem=400)

        with _mock_redeem_positions(withdrawable=Wei(10000)) as mocks:
            await redeem_positions(
                all_positions=[pos],
                os_token_positions=[pos],
                converter=make_converter(),
                nonce=5,
                block_number=BlockNumber(100),
            )

        submitted = _submitted_position(mocks)
        assert submitted.shares_to_redeem == Wei(400)

    async def test_preserves_original_leaf_shares_in_call(self) -> None:
        pos = make_position(leaf_shares=1000, processed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(10000)) as mocks:
            await redeem_positions(
                all_positions=[pos],
                os_token_positions=[pos],
                converter=make_converter(),
                nonce=5,
                block_number=BlockNumber(100),
            )

        submitted = _submitted_position(mocks)
        assert submitted.leaf_shares == Wei(1000)
        assert submitted.shares_to_redeem == Wei(500)

    async def test_meta_vault_position_raises(self) -> None:
        """A meta-vault position is unexpected and must surface as a RuntimeError."""
        pos = make_position(processed_shares=500)
        get_withdrawable = AsyncMock(return_value=Wei(10000))

        with _mock_redeem_positions(withdrawable=get_withdrawable, is_meta_vault=True) as mocks:
            with pytest.raises(RuntimeError, match='Unexpected meta vault position'):
                await redeem_positions(
                    all_positions=[pos],
                    os_token_positions=[pos],
                    converter=make_converter(100, 100),
                    nonce=5,
                    block_number=BlockNumber(100),
                )

        mocks['submit_mock'].assert_not_called()
        get_withdrawable.assert_not_called()

    async def test_unharvested_vault_skipped(self) -> None:
        """A vault that requires a state update is skipped without redeeming."""
        pos = make_position(processed_shares=500)

        with _mock_redeem_positions(
            withdrawable=Wei(10000),
            state_update_required=True,
        ) as mocks:
            await redeem_positions(
                all_positions=[pos],
                os_token_positions=[pos],
                converter=make_converter(100, 100),
                nonce=5,
                block_number=BlockNumber(100),
            )

        mocks['get_withdrawable'].assert_not_called()
        mocks['submit_mock'].assert_not_called()

    async def test_submit_failure_aborts_iteration(self) -> None:
        """A failed submission aborts the loop; subsequent positions are not attempted."""
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, processed_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, processed_shares=500)

        with _mock_redeem_positions(
            withdrawable=Wei(10000),
            submit_results=[None, BlockNumber(123)],
        ) as mocks:
            await redeem_positions(
                all_positions=[pos1, pos2],
                os_token_positions=[pos1, pos2],
                converter=make_converter(100, 100),
                nonce=5,
                block_number=BlockNumber(100),
            )

        # Only the first position is attempted; loop aborted
        assert mocks['submit_mock'].await_count == 1


# --- Async function tests (with mocks) ---


class TestSubmitRedeemPosition:
    async def test_success_returns_receipt_block(self) -> None:
        position = make_position(leaf_shares=1000, shares_to_redeem=500)
        with _mock_submit_redeem_position(tx_status=1) as mocks:
            result = await _submit_redeem_position(
                position=position,
                all_positions=[position],
                nonce=5,
            )
        assert result == BlockNumber(456)
        mocks['transaction_gas_wrapper'].assert_awaited_once()
        mocks['client'].eth.wait_for_transaction_receipt.assert_awaited_once()

    async def test_tx_status_zero_returns_none(self) -> None:
        """A reverted on-chain tx returns None without raising."""
        position = make_position(leaf_shares=1000, shares_to_redeem=500)
        with _mock_submit_redeem_position(tx_status=0):
            result = await _submit_redeem_position(
                position=position,
                all_positions=[position],
                nonce=5,
            )
        assert result is None

    @pytest.mark.parametrize('exc_class', [Web3Exception, RuntimeError, ValueError])
    async def test_tx_build_failure_returns_none(self, exc_class: type[Exception]) -> None:
        """Each caught exception during tx build/send returns None."""
        position = make_position(leaf_shares=1000, shares_to_redeem=500)
        with _mock_submit_redeem_position(send_exception=exc_class('boom')) as mocks:
            result = await _submit_redeem_position(
                position=position,
                all_positions=[position],
                nonce=5,
            )
        assert result is None
        # Receipt is never awaited when the build step raised
        mocks['client'].eth.wait_for_transaction_receipt.assert_not_awaited()

    async def test_unexpected_exception_propagates(self) -> None:
        """Exceptions outside the (Web3Exception, RuntimeError, ValueError) catch list propagate."""
        position = make_position(leaf_shares=1000, shares_to_redeem=500)
        with _mock_submit_redeem_position(send_exception=KeyError('boom')):
            with pytest.raises(KeyError):
                await _submit_redeem_position(
                    position=position,
                    all_positions=[position],
                    nonce=5,
                )


class TestProcessExitQueue:
    async def test_cannot_process(self) -> None:
        with patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer:
            mock_redeemer.can_process_exit_queue = AsyncMock(return_value=False)
            await _process_exit_queue(BlockNumber(100))
            mock_redeemer.process_exit_queue.assert_not_called()

    @pytest.mark.parametrize('tx_status', [1, 0])
    async def test_process_exit_queue(self, tx_status: int) -> None:
        mock_client = AsyncMock()
        mock_client.eth.wait_for_transaction_receipt = AsyncMock(return_value={'status': tx_status})
        with (
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(f'{MODULE}.execution_client', new=mock_client),
            patch(f'{MODULE}.settings') as mock_settings,
        ):
            mock_settings.execution_transaction_timeout = 120
            mock_redeemer.can_process_exit_queue = AsyncMock(return_value=True)
            mock_redeemer.process_exit_queue = AsyncMock(return_value='0xabc')
            await _process_exit_queue(BlockNumber(100))
            mock_redeemer.process_exit_queue.assert_called_once()


class TestStartupCheck:
    async def test_authorized(self) -> None:
        wallet_address = faker.eth_address()
        mock_wallet = MagicMock()
        mock_wallet.account.address = wallet_address
        with (
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(f'{MODULE}.wallet', new=mock_wallet),
        ):
            mock_redeemer.positions_manager = AsyncMock(return_value=wallet_address)
            await _startup_check()

    async def test_unauthorized(self) -> None:
        mock_wallet = MagicMock()
        mock_wallet.account.address = faker.eth_address()
        with (
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
            patch(f'{MODULE}.wallet', new=mock_wallet),
        ):
            mock_redeemer.positions_manager = AsyncMock(return_value=faker.eth_address())
            with pytest.raises(RuntimeError, match='Position Manager role must be assigned'):
                await _startup_check()


class TestProcess:
    async def test_no_queued_shares(self) -> None:
        with _mock_process() as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(0))
            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(1))

    async def test_below_threshold(self) -> None:
        with _mock_process() as mocks:
            # 500 wei queued shares, threshold is 1000 Gwei
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(500))
            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(1000))
            mocks['mock_redeem'].assert_not_called()

    async def test_gas_price_check_fails(self) -> None:
        """check_gas_price → False short-circuits before exit_queue or redemption work."""
        with (
            _mock_process() as mocks,
            patch(f'{MODULE}.check_gas_price', new=AsyncMock(return_value=False)),
        ):
            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(0))
        mocks['mock_redeemer'].queued_shares.assert_not_called()
        mocks['mock_redeem'].assert_not_called()

    async def test_zero_nonce_skipped(self) -> None:
        """nonce == 0 skips the round before any state mutation. Guards prev_nonce = nonce - 1."""
        with _mock_process() as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=0)
            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(0))
        mocks['mock_redeem'].assert_not_called()

    async def test_no_positions_from_ipfs(self) -> None:
        """Empty IPFS positions: skip redeem_positions."""
        with _mock_process(positions=[]) as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=5)
            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(0))
        mocks['mock_redeem'].assert_not_called()

    async def test_no_eligible_positions(self) -> None:
        """IPFS returns positions but assign_shares_to_redeem filters them all out."""
        pos = make_position(leaf_shares=1000)
        with (
            _mock_process(positions=[pos]) as mocks,
            patch(f'{MODULE}.assign_shares_to_redeem', new=AsyncMock(return_value=[])),
        ):
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=5)
            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(0))
        mocks['mock_redeem'].assert_not_called()

    async def test_successful_redemption(self) -> None:
        positions = [make_position(leaf_shares=1000, processed_shares=500, shares_to_redeem=500)]

        with _mock_process(positions=positions) as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=5)

            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(0))

        mocks['mock_redeem'].assert_awaited_once()
        redeem_call = mocks['mock_redeem'].await_args
        # nonce is passed directly; _build_multi_proof uses nonce - 1 internally
        assert redeem_call.kwargs['nonce'] == 5


# --- Helpers ---


@contextmanager
def _mock_redeem_positions(
    withdrawable: Wei | AsyncMock | None = None,
    is_meta_vault: bool = False,
    state_update_required: bool = False,
    submit_results: list[BlockNumber | None] | None = None,
) -> Iterator[dict[str, MagicMock]]:
    """Mock setup for redeem_positions tests.

    ``withdrawable`` may be a constant Wei value (returned on every call) or an
    AsyncMock for fine-grained control (e.g. ``side_effect=[...]`` for sequenced returns).
    ``state_update_required`` drives VaultContract.is_state_update_required, which gates
    the unharvested-vault skip. ``submit_results`` controls per-call return values of
    _submit_redeem_position; a ``None`` entry models a failed submission that should
    abort the round.
    """
    if isinstance(withdrawable, AsyncMock):
        get_withdrawable = withdrawable
    else:
        get_withdrawable = AsyncMock(
            return_value=withdrawable if withdrawable is not None else Wei(0)
        )

    if submit_results is not None:
        submit_mock = AsyncMock(side_effect=submit_results)
    else:
        submit_mock = AsyncMock(return_value=BlockNumber(123))

    vault_contract = MagicMock()
    vault_contract.is_state_update_required = AsyncMock(return_value=state_update_required)

    with (
        patch(f'{MODULE}.get_withdrawable_assets', new=get_withdrawable),
        patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=is_meta_vault)),
        patch(f'{MODULE}.VaultContract', return_value=vault_contract),
        patch(f'{MODULE}._submit_redeem_position', new=submit_mock),
        patch(
            f'{MODULE}.wait_for_execution_endpoints_synced',
            new=AsyncMock(),
        ) as wait_synced_mock,
    ):
        yield {
            'submit_mock': submit_mock,
            'wait_synced_mock': wait_synced_mock,
            'get_withdrawable': get_withdrawable,
        }


def _submitted_position(mocks: dict[str, MagicMock], index: int = 0) -> OsTokenPosition:
    """Return the position passed to the Nth _submit_redeem_position call."""
    return mocks['submit_mock'].call_args_list[index].kwargs['position']


@contextmanager
def _mock_submit_redeem_position(
    tx_status: int = 1,
    send_exception: BaseException | None = None,
) -> Iterator[dict[str, MagicMock]]:
    """Mock setup for _submit_redeem_position tests.

    ``send_exception`` makes ``transaction_gas_wrapper`` raise; otherwise it returns
    a fake tx that resolves to a receipt with the given ``tx_status``.
    """
    tx = HexBytes(b'\xab' * 32)
    mock_client = AsyncMock()
    mock_client.eth.wait_for_transaction_receipt = AsyncMock(
        return_value={'status': tx_status, 'blockNumber': BlockNumber(456)},
    )

    if send_exception is not None:
        gas_wrapper = AsyncMock(side_effect=send_exception)
    else:
        gas_wrapper = AsyncMock(return_value=tx)

    with (
        patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        patch(f'{MODULE}.transaction_gas_wrapper', new=gas_wrapper),
        patch(f'{MODULE}.execution_client', new=mock_client),
        patch(f'{MODULE}.settings') as mock_settings,
    ):
        mock_settings.execution_transaction_timeout = 120
        mock_redeemer.contract.functions.redeemOsTokenPositions = MagicMock()
        yield {
            'redeemer': mock_redeemer,
            'transaction_gas_wrapper': gas_wrapper,
            'client': mock_client,
        }


@contextmanager
def _mock_process(
    positions: list[OsTokenPosition] | None = None,
) -> Iterator[dict[str, MagicMock]]:
    """Common mock setup for process() tests."""
    positions = positions or []
    mock_client = MagicMock()
    block_number_future: asyncio.Future[BlockNumber] = asyncio.Future()
    block_number_future.set_result(BlockNumber(101))
    mock_client.eth.block_number = block_number_future

    with (
        patch(f'{MODULE}.check_gas_price', new=AsyncMock(return_value=True)),
        patch(f'{MODULE}._process_exit_queue', new=AsyncMock()),
        patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        patch(
            f'{MODULE}.create_os_token_converter',
            new=AsyncMock(return_value=make_converter()),
        ),
        patch(f'{MODULE}.settings') as mock_settings,
        patch(f'{MODULE}.get_finalized_block_number', new=AsyncMock(return_value=BlockNumber(100))),
        patch(f'{MODULE}.update_positions_cache', new=AsyncMock()),
        patch(
            f'{MODULE}.cached_fetch_positions_from_ipfs',
            new=AsyncMock(return_value=positions),
        ),
        patch(
            f'{MODULE}.fetch_positions_with_processed_shares',
            new=AsyncMock(return_value=positions),
        ),
        patch(
            f'{MODULE}.assign_shares_to_redeem',
            new=AsyncMock(return_value=positions),
        ),
        patch(
            f'{MODULE}.update_processed_shares_cache',
            new=AsyncMock(),
        ),
        patch(
            f'{MODULE}.redeem_positions',
            new=AsyncMock(),
        ) as mock_redeem,
        patch(f'{MODULE}.execution_client', new=mock_client),
    ):
        mock_settings.network_config.VAULT_BALANCE_SYMBOL = 'ETH'
        yield {
            'mock_redeemer': mock_redeemer,
            'mock_redeem': mock_redeem,
        }


def make_converter(total_assets: int = 110, total_shares: int = 100) -> OsTokenConverter:
    return OsTokenConverter(Wei(total_assets), Wei(total_shares))


def make_position(
    vault: ChecksumAddress = VAULT_1,
    owner: ChecksumAddress = OWNER_1,
    leaf_shares: int = 1000,
    processed_shares: int = 500,
    shares_to_redeem: int | None = None,
) -> OsTokenPosition:
    """Build a test position.

    ``processed_shares`` defaults to half of ``leaf_shares`` so redemption-loop
    tests don't silently no-op when a caller forgets to set it.

    ``shares_to_redeem`` defaults to ``leaf_shares - processed_shares``
    (i.e. unprocessed shares), mirroring what ``assign_shares_to_redeem`` would set
    before handing positions to ``redeem_positions``.  Pass an explicit value
    when testing the partial-fill or zero-withdrawable edge cases.
    """
    effective_shares_to_redeem = (
        shares_to_redeem if shares_to_redeem is not None else leaf_shares - processed_shares
    )
    return OsTokenPosition(
        vault=vault,
        owner=owner,
        leaf_shares=Wei(leaf_shares),
        processed_shares=Wei(processed_shares),
        shares_to_redeem=Wei(effective_shares_to_redeem),
    )
