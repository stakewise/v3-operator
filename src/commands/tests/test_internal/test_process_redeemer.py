import asyncio
from contextlib import contextmanager
from typing import Iterator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from eth_typing import BlockNumber, ChecksumAddress, HexStr
from hexbytes import HexBytes
from sw_utils.tests import faker
from web3 import Web3
from web3.exceptions import Web3Exception
from web3.types import Gwei, Wei

from src.commands.internal.process_redeemer import (
    _build_meta_vault_redeem_order,
    _build_multi_proof,
    _process_exit_queue,
    _redeem_meta_vault_sub_vaults,
    _startup_check,
    _submit_redeem_position,
    calculate_redeemable_shares,
    fetch_positions_from_ipfs,
    process,
    redeem_positions,
    update_vaults_state,
)
from src.common.typings import HarvestParams
from src.meta_vault.exceptions import ClaimDelayNotPassedException
from src.meta_vault.typings import SubVaultRedemption
from src.redemptions.os_token_converter import OsTokenConverter
from src.redemptions.typings import OsTokenPosition

MODULE = 'src.commands.internal.process_redeemer'

VAULT_1 = Web3.to_checksum_address('0x' + '11' * 20)
VAULT_2 = Web3.to_checksum_address('0x' + '22' * 20)
VAULT_3 = Web3.to_checksum_address('0x' + '55' * 20)
OWNER_1 = Web3.to_checksum_address('0x' + '33' * 20)
OWNER_2 = Web3.to_checksum_address('0x' + '44' * 20)
REGISTRY_1 = Web3.to_checksum_address('0x' + '66' * 20)


# --- Pure function tests (no mocks) ---


class TestBuildMultiProof:
    def test_single_position(self) -> None:
        position = make_position(leaf_shares=1000, unprocessed_shares=500)
        result = _build_multi_proof(
            tree_nonce=5,
            all_positions=[position],
            positions_to_redeem=[position],
        )
        assert len(result.leaves) == 1

    def test_partial_redeem(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, leaf_shares=1000, unprocessed_shares=500)
        pos2 = make_position(
            vault=VAULT_2, owner=OWNER_2, leaf_shares=2000, unprocessed_shares=1000
        )

        result = _build_multi_proof(
            tree_nonce=5,
            all_positions=[pos1, pos2],
            positions_to_redeem=[pos1],
        )
        assert len(result.leaves) == 1
        assert len(result.proof) > 0

    def test_all_positions_redeemed(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, leaf_shares=1000, unprocessed_shares=500)
        pos2 = make_position(
            vault=VAULT_2, owner=OWNER_2, leaf_shares=2000, unprocessed_shares=1000
        )

        result = _build_multi_proof(
            tree_nonce=5,
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
                queued_shares=10000,
                converter=make_converter(),
                tree_nonce=5,
            )
        mocks['submit_mock'].assert_not_called()

    async def test_single_position_sufficient_assets(self) -> None:
        position = make_position(unprocessed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(1000)) as mocks:
            await redeem_positions(
                all_positions=[position],
                os_token_positions=[position],
                queued_shares=10000,
                converter=make_converter(),
                tree_nonce=5,
            )

        assert mocks['submit_mock'].await_count == 1
        assert _submitted_position(mocks).shares_to_redeem == Wei(500)

    async def test_single_position_insufficient_assets_partial_fill(self) -> None:
        position = make_position(unprocessed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(100)) as mocks:
            await redeem_positions(
                all_positions=[position],
                os_token_positions=[position],
                queued_shares=10000,
                converter=make_converter(100, 100),
                tree_nonce=5,
            )

        assert mocks['submit_mock'].await_count == 1
        assert _submitted_position(mocks).shares_to_redeem == Wei(100)

    async def test_single_position_zero_withdrawable_skipped(self) -> None:
        position = make_position(unprocessed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(0)) as mocks:
            await redeem_positions(
                all_positions=[position],
                os_token_positions=[position],
                queued_shares=10000,
                converter=make_converter(100, 100),
                tree_nonce=5,
            )

        mocks['submit_mock'].assert_not_called()

    async def test_queued_shares_limits_redemption(self) -> None:
        position = make_position(unprocessed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(10000)) as mocks:
            await redeem_positions(
                all_positions=[position],
                os_token_positions=[position],
                queued_shares=200,
                converter=make_converter(),
                tree_nonce=5,
            )

        assert mocks['submit_mock'].await_count == 1
        assert _submitted_position(mocks).shares_to_redeem == Wei(200)

    async def test_multiple_positions_share_vault_cache(self) -> None:
        """Withdrawable is fetched once per vault, decremented after each redemption."""
        pos1 = make_position(owner=OWNER_1, unprocessed_shares=500)
        pos2 = make_position(owner=OWNER_2, unprocessed_shares=1000)

        get_withdrawable = AsyncMock(return_value=Wei(700))
        with _mock_redeem_positions(withdrawable=get_withdrawable) as mocks:
            await redeem_positions(
                all_positions=[pos1, pos2],
                os_token_positions=[pos1, pos2],
                queued_shares=10000,
                converter=make_converter(100, 100),
                tree_nonce=5,
            )

        # Two redemption transactions (one per position)
        assert mocks['submit_mock'].await_count == 2
        # Single fetch — second position uses cached value
        assert get_withdrawable.await_count == 1

        first_position = _submitted_position(mocks, 0)
        second_position = _submitted_position(mocks, 1)
        assert first_position.owner == OWNER_1 and first_position.shares_to_redeem == Wei(500)
        assert second_position.owner == OWNER_2 and second_position.shares_to_redeem == Wei(200)

    async def test_stops_across_vaults_when_queued_shares_exhausted(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, unprocessed_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, unprocessed_shares=800)

        with _mock_redeem_positions(withdrawable=Wei(10000)) as mocks:
            await redeem_positions(
                all_positions=[pos1, pos2],
                os_token_positions=[pos1, pos2],
                queued_shares=500,
                converter=make_converter(100, 100),
                tree_nonce=5,
            )

        # Only the first position's vault is redeemed
        assert mocks['submit_mock'].await_count == 1
        assert _submitted_position(mocks).vault == VAULT_1

    async def test_preserves_original_leaf_shares_in_call(self) -> None:
        pos = make_position(leaf_shares=1000, unprocessed_shares=500)

        with _mock_redeem_positions(withdrawable=Wei(10000)) as mocks:
            await redeem_positions(
                all_positions=[pos],
                os_token_positions=[pos],
                queued_shares=200,
                converter=make_converter(),
                tree_nonce=5,
            )

        submitted = _submitted_position(mocks)
        # leafShares preserved, sharesToRedeem capped by queued_shares
        assert submitted.leaf_shares == Wei(1000)
        assert submitted.shares_to_redeem == Wei(200)

    async def test_meta_vault_redeem_sub_vaults_when_short(self) -> None:
        """Meta vault short on withdrawable triggers sub-vault redemption then refetches.

        After the redemption, the caller must wait for fallback execution endpoints to
        catch up to the receipt block before re-reading withdrawable, otherwise a stale
        read can underestimate available assets.
        """
        pos = make_position(unprocessed_shares=500)
        # First call: short. Second call (post sub-vault redeem): plenty.
        get_withdrawable = AsyncMock(side_effect=[Wei(100), Wei(1000)])

        with (
            _mock_redeem_positions(withdrawable=get_withdrawable, is_meta_vault=True) as mocks,
            patch(
                f'{MODULE}._redeem_meta_vault_sub_vaults',
                new=AsyncMock(return_value=BlockNumber(900)),
            ) as mock_redeem_sub,
        ):
            await redeem_positions(
                all_positions=[pos],
                os_token_positions=[pos],
                queued_shares=10000,
                converter=make_converter(100, 100),
                tree_nonce=5,
            )

        mock_redeem_sub.assert_awaited_once()
        # Sync barrier called with the receipt block before re-reading withdrawable.
        mocks['wait_synced_mock'].assert_any_await(BlockNumber(900))
        assert get_withdrawable.await_count == 2
        assert _submitted_position(mocks).shares_to_redeem == Wei(500)

    async def test_meta_vault_redeem_no_successful_tx_skips_sync_barrier(self) -> None:
        """If sub-vault redemption submitted no successful tx, no sync barrier is needed."""
        pos = make_position(unprocessed_shares=500)
        get_withdrawable = AsyncMock(side_effect=[Wei(100), Wei(1000)])

        with (
            _mock_redeem_positions(withdrawable=get_withdrawable, is_meta_vault=True) as mocks,
            patch(
                f'{MODULE}._redeem_meta_vault_sub_vaults',
                new=AsyncMock(return_value=None),
            ),
        ):
            await redeem_positions(
                all_positions=[pos],
                os_token_positions=[pos],
                queued_shares=10000,
                converter=make_converter(100, 100),
                tree_nonce=5,
            )

        # Only the post-position-submit sync, not a sub-vault sync.
        mocks['wait_synced_mock'].assert_awaited_once_with(BlockNumber(123))

    async def test_meta_vault_redeem_still_short_partial_fill(self) -> None:
        """Sub-vault redemption helped but didn't fully cover — partial fill."""
        pos = make_position(unprocessed_shares=500)
        get_withdrawable = AsyncMock(side_effect=[Wei(100), Wei(300)])

        with (
            _mock_redeem_positions(withdrawable=get_withdrawable, is_meta_vault=True) as mocks,
            patch(
                f'{MODULE}._redeem_meta_vault_sub_vaults',
                new=AsyncMock(return_value=BlockNumber(900)),
            ),
        ):
            await redeem_positions(
                all_positions=[pos],
                os_token_positions=[pos],
                queued_shares=10000,
                converter=make_converter(100, 100),
                tree_nonce=5,
            )

        assert _submitted_position(mocks).shares_to_redeem == Wei(300)

    async def test_meta_vault_cache_writeback_persists_across_positions(self) -> None:
        """Refetched withdrawable is written back to the cache and reused for the next
        position from the same meta vault — no extra fetch."""
        pos1 = make_position(owner=OWNER_1, unprocessed_shares=500)
        pos2 = make_position(owner=OWNER_2, unprocessed_shares=300)
        # 1st: pre-refetch (short for pos1). 2nd: post-refetch (covers both positions).
        get_withdrawable = AsyncMock(side_effect=[Wei(100), Wei(2000)])

        with (
            _mock_redeem_positions(withdrawable=get_withdrawable, is_meta_vault=True) as mocks,
            patch(
                f'{MODULE}._redeem_meta_vault_sub_vaults',
                new=AsyncMock(return_value=BlockNumber(900)),
            ),
        ):
            await redeem_positions(
                all_positions=[pos1, pos2],
                os_token_positions=[pos1, pos2],
                queued_shares=10000,
                converter=make_converter(100, 100),
                tree_nonce=5,
            )

        # Two redemptions executed. Two fetches total — pos2 reads from the cache
        # the refetch populated. If the cache writeback is removed, pos2 would
        # trigger a third fetch.
        assert mocks['submit_mock'].await_count == 2
        assert get_withdrawable.await_count == 2
        assert _submitted_position(mocks, 0).shares_to_redeem == Wei(500)
        assert _submitted_position(mocks, 1).shares_to_redeem == Wei(300)

    async def test_submit_failure_aborts_iteration(self) -> None:
        """A failed submission aborts the loop; subsequent positions are not attempted."""
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, unprocessed_shares=500)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, unprocessed_shares=500)

        with _mock_redeem_positions(
            withdrawable=Wei(10000),
            submit_results=[None, BlockNumber(123)],
        ) as mocks:
            await redeem_positions(
                all_positions=[pos1, pos2],
                os_token_positions=[pos1, pos2],
                queued_shares=10000,
                converter=make_converter(100, 100),
                tree_nonce=5,
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
                tree_nonce=5,
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
                tree_nonce=5,
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
                tree_nonce=5,
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
                    tree_nonce=5,
                )


class TestFetchPositionsFromIpfs:
    async def test_empty_positions(self) -> None:
        async def empty_gen(block_number: BlockNumber | None = None):  # type: ignore[misc]
            return
            yield  # noqa: unreachable

        with patch(f'{MODULE}.iter_os_token_positions', side_effect=empty_gen):
            result = await fetch_positions_from_ipfs(block_number=BlockNumber(100))
        assert result == []

    async def test_returns_all_positions(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, leaf_shares=1000)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, leaf_shares=2000)

        async def gen(block_number: BlockNumber | None = None):  # type: ignore[misc]
            yield pos1
            yield pos2

        with patch(f'{MODULE}.iter_os_token_positions', side_effect=gen):
            result = await fetch_positions_from_ipfs(block_number=BlockNumber(100))
        assert len(result) == 2
        assert result[0] is pos1
        assert result[1] is pos2


class TestCalculateRedeemableShares:
    async def test_all_shares_processed(self) -> None:
        pos = make_position(leaf_shares=1000)
        with patch(
            f'{MODULE}.get_processed_shares_batch',
            new=AsyncMock(return_value=[Wei(1000)]),
        ):
            result = await calculate_redeemable_shares(
                [pos], nonce=5, block_number=BlockNumber(100)
            )
        assert result == []

    async def test_partial_processed_shares(self) -> None:
        pos = make_position(leaf_shares=1000)
        with patch(
            f'{MODULE}.get_processed_shares_batch',
            new=AsyncMock(return_value=[Wei(300)]),
        ):
            result = await calculate_redeemable_shares(
                [pos], nonce=5, block_number=BlockNumber(100)
            )
        assert len(result) == 1
        assert result[0].unprocessed_shares == Wei(700)
        assert result[0].leaf_shares == Wei(1000)

    async def test_multiple_positions_mixed(self) -> None:
        pos1 = make_position(vault=VAULT_1, owner=OWNER_1, leaf_shares=1000)
        pos2 = make_position(vault=VAULT_2, owner=OWNER_2, leaf_shares=2000)

        with patch(
            f'{MODULE}.get_processed_shares_batch',
            new=AsyncMock(return_value=[Wei(1000), Wei(500)]),
        ):
            result = await calculate_redeemable_shares(
                [pos1, pos2], nonce=5, block_number=BlockNumber(100)
            )
        assert len(result) == 1
        assert result[0].owner == OWNER_2
        assert result[0].unprocessed_shares == Wei(1500)


class TestUpdateVaultsState:
    async def test_no_vaults(self) -> None:
        with _mock_update_vaults_state() as mocks:
            await update_vaults_state(vaults=[], block_number=BlockNumber(100))
        mocks['update_state'].assert_not_called()
        mocks['harvest_params'].assert_not_called()

    @pytest.mark.parametrize(
        'needs_update, expected_calls',
        [(True, 1), (False, 0)],
        ids=['needs_update', 'up_to_date'],
    )
    async def test_meta_vault_update_state_gated_by_needs_update(
        self, needs_update: bool, expected_calls: int
    ) -> None:
        """meta_vault_tree_update_state runs iff is_meta_vault_state_update_required is True.
        When it does, the corresponding Vault entry from meta_vaults_map is forwarded
        by identity along with the full meta_vaults_map."""
        root_meta_vault = MagicMock()
        meta_vaults_map = {VAULT_1: root_meta_vault}
        with _mock_update_vaults_state(
            needs_update=needs_update,
            meta_vaults_map=meta_vaults_map,
        ) as mocks:
            await update_vaults_state(vaults=[VAULT_1], block_number=BlockNumber(100))

        assert mocks['update_state'].await_count == expected_calls
        if needs_update:
            mocks['graph_get_vaults'].assert_awaited_once_with(is_meta_vault=True)
            assert mocks['update_state'].await_args.kwargs['root_meta_vault'] is root_meta_vault
            assert mocks['update_state'].await_args.kwargs['meta_vaults_map'] is meta_vaults_map

    async def test_meta_vault_no_sub_vaults_skipped(self) -> None:
        """A meta vault with no sub-vaults is skipped — nothing to update."""
        empty_meta_vault = MagicMock()
        empty_meta_vault.sub_vaults = []
        with _mock_update_vaults_state(
            meta_vaults_map={VAULT_1: empty_meta_vault},
        ) as mocks:
            await update_vaults_state(vaults=[VAULT_1], block_number=BlockNumber(100))
        mocks['update_state'].assert_not_called()

    async def test_meta_vault_update_state_failure_raises(self) -> None:
        """A failure inside meta_vault_tree_update_state aborts the round."""
        with _mock_update_vaults_state(
            meta_vaults_map={VAULT_1: MagicMock()},
            update_state_exception=RuntimeError('boom'),
        ):
            with pytest.raises(RuntimeError, match='Failed to update meta vault tree state'):
                await update_vaults_state(vaults=[VAULT_1], block_number=BlockNumber(100))

    async def test_meta_vault_claim_delay_logged_and_continues(self) -> None:
        """ClaimDelayNotPassedException is caught, logged, and does not abort the round.

        Regular vaults batched alongside the meta vault are still processed.
        """
        exit_request = MagicMock()
        exit_request.vault = VAULT_1
        exit_request.position_ticket = 1234
        with _mock_update_vaults_state(
            meta_vaults_map={VAULT_1: MagicMock()},
            harvest_params={VAULT_2: make_harvest_params()},
            update_state_exception=ClaimDelayNotPassedException(exit_request),
        ) as mocks:
            await update_vaults_state(vaults=[VAULT_1, VAULT_2], block_number=BlockNumber(100))
        mocks['update_state'].assert_awaited_once()
        mocks['multicall'].tx_aggregate.assert_awaited_once_with(
            [(VAULT_2, ENCODED_UPDATE_STATE_CALL)]
        )

    @pytest.mark.parametrize(
        'has_params, expected_multicall_calls',
        [(True, 1), (False, 0)],
        ids=['with_params', 'no_params'],
    )
    async def test_regular_vault_multicall_gated_by_harvest_params(
        self, has_params: bool, expected_multicall_calls: int
    ) -> None:
        """A None entry in get_multiple_harvest_params skips that vault from the multicall."""
        params: HarvestParams | None = make_harvest_params() if has_params else None
        with _mock_update_vaults_state(harvest_params={VAULT_1: params}) as mocks:
            await update_vaults_state(vaults=[VAULT_1], block_number=BlockNumber(100))

        assert mocks['multicall'].tx_aggregate.await_count == expected_multicall_calls
        if has_params:
            mocks['multicall'].tx_aggregate.assert_awaited_once_with(
                [(VAULT_1, ENCODED_UPDATE_STATE_CALL)]
            )

    async def test_multicall_tx_failure_raises(self) -> None:
        """A failed multicall receipt aborts the round."""
        with _mock_update_vaults_state(
            harvest_params={VAULT_1: make_harvest_params()},
            multicall_tx_status=0,
        ):
            with pytest.raises(RuntimeError, match='Update State multicall tx failed'):
                await update_vaults_state(vaults=[VAULT_1], block_number=BlockNumber(100))

    async def test_mix_of_meta_and_regular_vaults(self) -> None:
        """Meta vault is harvested via meta_vault_tree_update_state; regular vaults are
        batched into a single multicall. Harvest params are fetched only for the
        regular vaults."""
        params = make_harvest_params()
        meta_vaults_map = {VAULT_1: MagicMock()}
        with _mock_update_vaults_state(
            meta_vaults_map=meta_vaults_map,
            harvest_params={VAULT_2: params},
        ) as mocks:
            await update_vaults_state(vaults=[VAULT_1, VAULT_2], block_number=BlockNumber(100))

        mocks['update_state'].assert_awaited_once()
        assert (
            mocks['update_state'].await_args.kwargs['root_meta_vault'] is meta_vaults_map[VAULT_1]
        )
        mocks['harvest_params'].assert_awaited_once_with([VAULT_2], BlockNumber(100))
        mocks['multicall'].tx_aggregate.assert_awaited_once_with(
            [(VAULT_2, ENCODED_UPDATE_STATE_CALL)]
        )


class TestRedeemMetaVaultSubVaults:
    async def test_successful_redeem(self) -> None:
        with (
            patch(
                f'{MODULE}._build_meta_vault_redeem_order',
                new=AsyncMock(return_value=[SubVaultRedemption(vault=VAULT_1, assets=Wei(400))]),
            ),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        ):
            mock_redeemer.redeem_sub_vaults_assets = AsyncMock(
                return_value=('0xabc', BlockNumber(789))
            )
            result = await _redeem_meta_vault_sub_vaults(vault_address=VAULT_1, assets=Wei(400))
        mock_redeemer.redeem_sub_vaults_assets.assert_awaited_once_with(VAULT_1, Wei(400))
        assert result == BlockNumber(789)

    @pytest.mark.parametrize('exc_class', [Web3Exception, RuntimeError, ValueError])
    async def test_failed_redeem_aborts_sequence(self, exc_class: type[Exception]) -> None:
        """Each caught exception type stops the sequence; later entries are not attempted."""
        with (
            patch(
                f'{MODULE}._build_meta_vault_redeem_order',
                new=AsyncMock(
                    return_value=[
                        SubVaultRedemption(vault=VAULT_2, assets=Wei(200)),
                        SubVaultRedemption(vault=VAULT_1, assets=Wei(400)),
                    ]
                ),
            ),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        ):
            mock_redeemer.redeem_sub_vaults_assets = AsyncMock(side_effect=exc_class('fail'))
            result = await _redeem_meta_vault_sub_vaults(vault_address=VAULT_1, assets=Wei(400))
        mock_redeemer.redeem_sub_vaults_assets.assert_awaited_once_with(VAULT_2, Wei(200))
        assert result is None

    async def test_unexpected_exception_propagates(self) -> None:
        """Exceptions outside the (Web3Exception, RuntimeError, ValueError) catch list propagate."""
        with (
            patch(
                f'{MODULE}._build_meta_vault_redeem_order',
                new=AsyncMock(return_value=[SubVaultRedemption(vault=VAULT_2, assets=Wei(200))]),
            ),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        ):
            mock_redeemer.redeem_sub_vaults_assets = AsyncMock(side_effect=KeyError('boom'))
            with pytest.raises(KeyError):
                await _redeem_meta_vault_sub_vaults(vault_address=VAULT_1, assets=Wei(400))

    async def test_first_succeeds_second_fails(self) -> None:
        """First sub-vault redemption succeeds; subsequent failure aborts after the second call.

        The block of the last successful tx is returned so the caller can sync endpoints.
        """
        with (
            patch(
                f'{MODULE}._build_meta_vault_redeem_order',
                new=AsyncMock(
                    return_value=[
                        SubVaultRedemption(vault=VAULT_2, assets=Wei(200)),
                        SubVaultRedemption(vault=VAULT_1, assets=Wei(400)),
                    ]
                ),
            ),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        ):
            mock_redeemer.redeem_sub_vaults_assets = AsyncMock(
                side_effect=[('0xabc', BlockNumber(700)), RuntimeError('fail')]
            )
            result = await _redeem_meta_vault_sub_vaults(vault_address=VAULT_1, assets=Wei(400))

        calls = mock_redeemer.redeem_sub_vaults_assets.call_args_list
        assert len(calls) == 2
        assert calls[0].args == (VAULT_2, Wei(200))
        assert calls[1].args == (VAULT_1, Wei(400))
        assert result == BlockNumber(700)

    async def test_nested_meta_vault_all_succeed(self) -> None:
        """Nested meta vault is redeemed before parent, in order; last receipt block returned."""
        with (
            patch(
                f'{MODULE}._build_meta_vault_redeem_order',
                new=AsyncMock(
                    return_value=[
                        SubVaultRedemption(vault=VAULT_2, assets=Wei(200)),
                        SubVaultRedemption(vault=VAULT_1, assets=Wei(400)),
                    ]
                ),
            ),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        ):
            mock_redeemer.redeem_sub_vaults_assets = AsyncMock(
                side_effect=[('0xabc', BlockNumber(700)), ('0xdef', BlockNumber(800))]
            )
            result = await _redeem_meta_vault_sub_vaults(vault_address=VAULT_1, assets=Wei(400))

        calls = mock_redeemer.redeem_sub_vaults_assets.call_args_list
        assert len(calls) == 2
        assert calls[0].args == (VAULT_2, Wei(200))
        assert calls[1].args == (VAULT_1, Wei(400))
        assert result == BlockNumber(800)

    async def test_build_order_failure_returns_silently(self) -> None:
        """Failure to build the redeem order is logged and swallowed."""
        with (
            patch(
                f'{MODULE}._build_meta_vault_redeem_order',
                new=AsyncMock(side_effect=RuntimeError('boom')),
            ),
            patch(f'{MODULE}.os_token_redeemer_contract') as mock_redeemer,
        ):
            mock_redeemer.redeem_sub_vaults_assets = AsyncMock()
            result = await _redeem_meta_vault_sub_vaults(vault_address=VAULT_1, assets=Wei(400))
        mock_redeemer.redeem_sub_vaults_assets.assert_not_called()
        assert result is None


class TestBuildMetaVaultRedeemOrder:
    async def test_flat_meta_vault_no_nesting(self) -> None:
        """Meta vault with only regular sub-vaults returns single entry."""
        mock_registry = AsyncMock()
        mock_registry.calculate_sub_vaults_redemptions = AsyncMock(return_value=[])

        with (
            patch(f'{MODULE}.MetaVaultContract') as mock_mv_cls,
            patch(f'{MODULE}.SubVaultsRegistryContract', return_value=mock_registry),
            patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=False)),
        ):
            mock_mv_cls.return_value.sub_vaults_registry = AsyncMock(return_value=REGISTRY_1)
            result = await _build_meta_vault_redeem_order(VAULT_1, Wei(400))

        assert result == [SubVaultRedemption(vault=VAULT_1, assets=Wei(400))]

    async def test_nested_meta_vault(self) -> None:
        """MetaVault A has sub-vault B (meta vault). Order: B first, then A."""
        redemption_b = SubVaultRedemption(vault=VAULT_2, assets=Wei(200))
        redemption_c = SubVaultRedemption(vault=VAULT_3, assets=Wei(100))

        # Registry for A returns B (meta) and C (regular)
        mock_registry_a = AsyncMock()
        mock_registry_a.calculate_sub_vaults_redemptions = AsyncMock(
            return_value=[redemption_b, redemption_c]
        )
        # Registry for B returns no nested meta vaults
        mock_registry_b = AsyncMock()
        mock_registry_b.calculate_sub_vaults_redemptions = AsyncMock(return_value=[])

        registry_a = Web3.to_checksum_address('0x' + 'aa' * 20)
        registry_b = Web3.to_checksum_address('0x' + 'bb' * 20)

        async def mock_is_meta_vault(addr: ChecksumAddress) -> bool:
            return addr in (VAULT_1, VAULT_2)

        def mock_meta_vault_contract(addr: ChecksumAddress) -> MagicMock:
            m = MagicMock()
            if addr == VAULT_1:
                m.sub_vaults_registry = AsyncMock(return_value=registry_a)
            else:
                m.sub_vaults_registry = AsyncMock(return_value=registry_b)
            return m

        def mock_registry_contract(addr: ChecksumAddress) -> AsyncMock:
            if addr == registry_a:
                return mock_registry_a
            return mock_registry_b

        with (
            patch(f'{MODULE}.MetaVaultContract', side_effect=mock_meta_vault_contract),
            patch(f'{MODULE}.SubVaultsRegistryContract', side_effect=mock_registry_contract),
            patch(f'{MODULE}.is_meta_vault', side_effect=mock_is_meta_vault),
        ):
            result = await _build_meta_vault_redeem_order(VAULT_1, Wei(400))

        assert result == [
            SubVaultRedemption(vault=VAULT_2, assets=Wei(200)),
            SubVaultRedemption(vault=VAULT_1, assets=Wei(400)),
        ]

    async def test_skips_zero_asset_redemptions(self) -> None:
        """Sub-vaults with zero assets are not recursed into."""
        redemption = SubVaultRedemption(vault=VAULT_2, assets=Wei(0))
        mock_registry = AsyncMock()
        mock_registry.calculate_sub_vaults_redemptions = AsyncMock(return_value=[redemption])

        with (
            patch(f'{MODULE}.MetaVaultContract') as mock_mv_cls,
            patch(f'{MODULE}.SubVaultsRegistryContract', return_value=mock_registry),
            patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=True)),
        ):
            mock_mv_cls.return_value.sub_vaults_registry = AsyncMock(return_value=REGISTRY_1)
            result = await _build_meta_vault_redeem_order(VAULT_1, Wei(400))

        assert result == [SubVaultRedemption(vault=VAULT_1, assets=Wei(400))]


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
        mocks['mock_update_state'].assert_not_called()
        mocks['mock_redeem'].assert_not_called()

    async def test_zero_nonce_skipped(self) -> None:
        """nonce == 0 skips the round before any state mutation. Guards prev_nonce = nonce - 1."""
        with _mock_process() as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=0)
            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(0))
        mocks['mock_update_state'].assert_not_called()
        mocks['mock_redeem'].assert_not_called()

    async def test_no_positions_from_ipfs(self) -> None:
        """Empty IPFS positions: skip update_vaults_state and redeem_positions."""
        with _mock_process(positions=[]) as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=5)
            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(0))
        mocks['mock_update_state'].assert_not_called()
        mocks['mock_redeem'].assert_not_called()

    async def test_no_eligible_positions(self) -> None:
        """IPFS returns positions but calculate_redeemable_shares filters them all out."""
        pos = make_position(leaf_shares=1000)
        with (
            _mock_process(positions=[pos]) as mocks,
            patch(f'{MODULE}.calculate_redeemable_shares', new=AsyncMock(return_value=[])),
        ):
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=5)
            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(0))
        mocks['mock_update_state'].assert_not_called()
        mocks['mock_redeem'].assert_not_called()

    async def test_successful_redemption(self) -> None:
        positions = [make_position(leaf_shares=1000, unprocessed_shares=500, shares_to_redeem=500)]

        with _mock_process(positions=positions) as mocks:
            mocks['mock_redeemer'].queued_shares = AsyncMock(return_value=Wei(1000))
            mocks['mock_redeemer'].nonce = AsyncMock(return_value=5)

            # Verify update_vaults_state runs before redeem_positions
            manager = MagicMock()
            manager.attach_mock(mocks['mock_update_state'], 'update_state')
            manager.attach_mock(mocks['mock_redeem'], 'redeem')

            await process(block_number=BlockNumber(100), min_queued_assets=Gwei(0))

        assert [c[0] for c in manager.mock_calls] == ['update_state', 'redeem']

        update_call = mocks['mock_update_state'].await_args
        # Unique vault list derived from os_token_positions
        assert update_call.kwargs['vaults'] == [VAULT_1]

        redeem_call = mocks['mock_redeem'].await_args
        # tree_nonce must use prev_nonce = nonce - 1 (off-by-one is critical)
        assert redeem_call.kwargs['tree_nonce'] == 4
        # queued_shares is forwarded as raw shares, not converted to assets
        assert redeem_call.kwargs['queued_shares'] == 1000


# --- Helpers ---


@contextmanager
def _mock_redeem_positions(
    withdrawable: Wei | AsyncMock | None = None,
    is_meta_vault: bool = False,
    submit_results: list[BlockNumber | None] | None = None,
) -> Iterator[dict[str, MagicMock]]:
    """Mock setup for redeem_positions tests.

    ``withdrawable`` may be a constant Wei value (returned on every call) or an
    AsyncMock for fine-grained control (e.g. ``side_effect=[...]`` for sequenced returns).
    ``submit_results`` controls per-call return values of _submit_redeem_position;
    a ``None`` entry models a failed submission that should abort the round.
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

    with (
        patch(f'{MODULE}.get_withdrawable_assets', new=get_withdrawable),
        patch(f'{MODULE}.is_meta_vault', new=AsyncMock(return_value=is_meta_vault)),
        patch(f'{MODULE}._submit_redeem_position', new=submit_mock),
        patch(
            f'{MODULE}.wait_for_execution_endpoints_synced',
            new=AsyncMock(),
        ) as wait_synced_mock,
    ):
        yield {
            'submit_mock': submit_mock,
            'wait_synced_mock': wait_synced_mock,
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


ENCODED_UPDATE_STATE_CALL = HexStr('0xdeadbeef')


@contextmanager
def _mock_update_vaults_state(
    needs_update: bool = True,
    harvest_params: dict[ChecksumAddress, HarvestParams | None] | None = None,
    meta_vaults_map: dict | None = None,
    update_state_exception: BaseException | None = None,
    multicall_tx_status: int = 1,
) -> Iterator[dict[str, MagicMock]]:
    """Mock setup for update_vaults_state tests.

    ``meta_vaults_map`` is the dict returned by graph_get_vaults; addresses present
    in this map are treated as meta vaults by update_vaults_state. ``harvest_params``
    is the dict returned by get_multiple_harvest_params; a None value for a vault
    skips it from the multicall (production behavior). ``update_state_exception``
    makes meta_vault_tree_update_state raise.
    """
    meta_vaults_map = {} if meta_vaults_map is None else meta_vaults_map
    harvest_params = {} if harvest_params is None else harvest_params

    if update_state_exception is not None:
        update_state_mock = AsyncMock(side_effect=update_state_exception)
    else:
        update_state_mock = AsyncMock()

    def vault_factory(addr: ChecksumAddress) -> MagicMock:
        mock_vault = MagicMock()
        mock_vault.contract_address = addr
        mock_vault.get_update_state_call = MagicMock(return_value=ENCODED_UPDATE_STATE_CALL)
        return mock_vault

    with (
        patch(
            f'{MODULE}.graph_get_vaults',
            new=AsyncMock(return_value=meta_vaults_map),
        ) as mock_graph,
        patch(
            f'{MODULE}.is_meta_vault_state_update_required',
            new=AsyncMock(return_value=needs_update),
        ),
        patch(f'{MODULE}.meta_vault_tree_update_state', new=update_state_mock),
        patch(
            f'{MODULE}.get_multiple_harvest_params',
            new=AsyncMock(return_value=harvest_params),
        ) as mock_harvest_params,
        patch(f'{MODULE}.VaultContract', side_effect=vault_factory) as mock_vault_cls,
        _mock_multicall_tx(tx_status=multicall_tx_status) as multicall_mocks,
    ):
        yield {
            'graph_get_vaults': mock_graph,
            'update_state': update_state_mock,
            'harvest_params': mock_harvest_params,
            'multicall': multicall_mocks['mock_multicall'],
            'vault_cls': mock_vault_cls,
        }


@contextmanager
def _mock_multicall_tx(tx_status: int = 1) -> Iterator[dict[str, MagicMock]]:
    """Mock multicall_contract.tx_aggregate with a fake tx hash + receipt status."""
    mock_client = AsyncMock()
    mock_client.eth.wait_for_transaction_receipt = AsyncMock(return_value={'status': tx_status})

    with (
        patch(f'{MODULE}.multicall_contract') as mock_multicall,
        patch(f'{MODULE}.execution_client', new=mock_client),
        patch(f'{MODULE}.settings') as mock_settings,
    ):
        mock_settings.execution_transaction_timeout = 120
        mock_multicall.tx_aggregate = AsyncMock(return_value='0x' + '11' * 32)
        yield {'mock_multicall': mock_multicall}


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
        patch(
            f'{MODULE}.fetch_positions_from_ipfs',
            new=AsyncMock(return_value=positions),
        ),
        patch(
            f'{MODULE}.calculate_redeemable_shares',
            new=AsyncMock(return_value=positions),
        ),
        patch(
            f'{MODULE}.update_vaults_state',
            new=AsyncMock(),
        ) as mock_update_state,
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
            'mock_update_state': mock_update_state,
        }


def make_converter(total_assets: int = 110, total_shares: int = 100) -> OsTokenConverter:
    return OsTokenConverter(Wei(total_assets), Wei(total_shares))


def make_position(
    vault: ChecksumAddress = VAULT_1,
    owner: ChecksumAddress = OWNER_1,
    leaf_shares: int = 1000,
    unprocessed_shares: int = 500,
    shares_to_redeem: int = 0,
) -> OsTokenPosition:
    """Build a test position. ``unprocessed_shares`` defaults to a non-zero value so
    redemption-loop tests don't silently no-op when a caller forgets to set it."""
    return OsTokenPosition(
        vault=vault,
        owner=owner,
        leaf_shares=Wei(leaf_shares),
        unprocessed_shares=Wei(unprocessed_shares),
        shares_to_redeem=Wei(shares_to_redeem),
    )


def make_harvest_params() -> HarvestParams:
    return HarvestParams(
        rewards_root=HexBytes(b'\x01' * 32),
        reward=Wei(100),
        unlocked_mev_reward=Wei(50),
        proof=[HexBytes(b'\x02' * 32)],
    )
