import asyncio
from contextlib import contextmanager
from typing import Iterator
from unittest import mock
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import ClientResponseError
from eth_typing import BlockNumber, HexStr
from sw_utils import ChainHead
from sw_utils.tests import faker
from web3.types import Gwei

from src.common.tests.factories import create_chain_head
from src.validators.builders_onboarding import (
    BUILDER_DEPOSITS_FILTER_APPLIED,
    get_validators_start_index,
    is_validator_approvals_blocked,
    mark_fresh_network_validators,
    resolve_builders_onboarding,
)
from src.validators.database import (
    BuilderDepositCrud,
    CheckpointCrud,
    NetworkValidatorCrud,
)
from src.validators.event_processors import NetworkValidatorsProcessor
from src.validators.exceptions import ValidatorIndexUnknownError
from src.validators.oracles import create_approval_request
from src.validators.relayer import RelayerClient
from src.validators.tasks import (
    register_new_validators,
    validate_index_and_register_validators,
)
from src.validators.tests.factories import (
    FORK_EPOCH,
    FORK_SLOT,
    create_consensus_validator,
    create_deposit_event,
    get_public_key,
    patch_block_slot,
    patch_deposit_signature,
    patch_tail_events,
    save_network_validator,
    set_network_validators_checkpoint,
)
from src.validators.typings import BuilderDeposit, NetworkValidator

CHAIN_HEAD_BLOCK = BlockNumber(1000)
FORK_BLOCK = BlockNumber(900)

pytestmark = pytest.mark.usefixtures('validators_db', 'fork_epoch')


class TestResolveBuildersOnboarding:
    async def test_not_run_before_fork(self):
        _save_builder_deposits(faker.validator_public_key())
        set_network_validators_checkpoint(CHAIN_HEAD_BLOCK)

        with _patch_consensus() as consensus_mock:
            await resolve_builders_onboarding(_chain_head(slot=FORK_SLOT - 1))

        consensus_mock.get_builders.assert_not_called()
        assert len(_builder_deposit_keys()) == 1
        assert _onboarding_checkpoint() is None

    @pytest.mark.parametrize('scanned_block', [None, CHAIN_HEAD_BLOCK - 1])
    async def test_waits_for_network_validators(self, scanned_block):
        if scanned_block is not None:
            set_network_validators_checkpoint(BlockNumber(scanned_block))

        with _patch_consensus() as consensus_mock:
            await resolve_builders_onboarding(_chain_head())

        consensus_mock.get_builders.assert_not_called()
        assert _onboarding_checkpoint() is None

    async def test_runs_once(self):
        set_network_validators_checkpoint(CHAIN_HEAD_BLOCK)

        with _patch_consensus() as consensus_mock:
            await resolve_builders_onboarding(_chain_head())
            await resolve_builders_onboarding(_chain_head(slot=FORK_SLOT + 1))

        consensus_mock.get_builders.assert_awaited_once_with(state_id=str(FORK_SLOT))
        assert _onboarding_checkpoint() == FORK_EPOCH

    @pytest.mark.parametrize('with_marker', [False, True])
    async def test_builder_deposits_resolved(self, with_marker):
        validator_key = faker.validator_public_key()
        builder_key = faker.validator_public_key()
        _save_builder_deposits(validator_key, builder_key)
        set_network_validators_checkpoint(CHAIN_HEAD_BLOCK)
        if with_marker:
            _set_filter_marker()

        with _patch_consensus(), _patch_validators([validator_key]) as validators_mock:
            await resolve_builders_onboarding(_chain_head())

        # validators are looked up at the chain head
        validators_mock.assert_awaited_once_with(
            [validator_key, builder_key], slot=str(FORK_SLOT + 10)
        )
        assert NetworkValidatorCrud().get_registered_public_keys([validator_key, builder_key]) == {
            validator_key
        }
        assert _builder_deposit_keys() == []
        assert _onboarding_checkpoint() == FORK_EPOCH

    @pytest.mark.parametrize('with_marker', [False, True])
    # pylint: disable-next=too-many-locals
    async def test_removal_rule(self, with_marker):
        builder_only = faker.validator_public_key()
        invalid_pending = faker.validator_public_key()
        builder_and_validator = faker.validator_public_key()
        valid_pending = faker.validator_public_key()
        post_fork_deposit = faker.validator_public_key()
        post_fork_builder = faker.validator_public_key()
        regular_validator = faker.validator_public_key()

        NetworkValidatorCrud().save_network_validators(
            [
                NetworkValidator(public_key=key, block_number=BlockNumber(10))
                for key in (
                    builder_only,
                    invalid_pending,
                    builder_and_validator,
                    valid_pending,
                    post_fork_deposit,
                    regular_validator,
                )
            ]
        )
        set_network_validators_checkpoint(CHAIN_HEAD_BLOCK)
        if with_marker:
            _set_filter_marker()

        pending_deposits = [
            _pending_deposit(invalid_pending, signature='0x' + '11' * 96),
            _pending_deposit(valid_pending, signature='0x' + '22' * 96),
        ]
        consensus_mock = _consensus_mock(
            builders=[
                builder_only,
                invalid_pending,
                builder_and_validator,
                valid_pending,
                post_fork_deposit,
                post_fork_builder,
            ],
            pending_deposits=pending_deposits,
        )
        deposit_events = [create_deposit_event(public_key=post_fork_deposit, block_number=950)]

        with _patch_consensus(consensus_mock), _patch_validators(
            [builder_and_validator, regular_validator]
        ) as validators_mock, mock.patch(
            'src.validators.builders_onboarding.is_valid_deposit_data_signature',
            side_effect=lambda *args: args[2] == bytes.fromhex('22' * 96),
        ), patch_deposit_signature(), mock.patch(
            'src.validators.builders_onboarding.validators_registry_contract.get_deposit_events',
            return_value=deposit_events,
        ) as events_mock:
            await resolve_builders_onboarding(_chain_head())

        # validators are looked up at the chain head
        assert validators_mock.await_args.kwargs['slot'] == str(FORK_SLOT + 10)
        events_mock.assert_awaited_once_with(from_block=FORK_BLOCK, to_block=CHAIN_HEAD_BLOCK)

        registered = NetworkValidatorCrud().get_registered_public_keys(
            [
                builder_only,
                invalid_pending,
                builder_and_validator,
                valid_pending,
                post_fork_deposit,
                post_fork_builder,
                regular_validator,
            ]
        )
        assert registered == {
            builder_and_validator,
            valid_pending,
            post_fork_deposit,
            regular_validator,
        }
        assert _onboarding_checkpoint() == FORK_EPOCH

    async def test_deposit_events_from_fork_block(self):
        builder_only = save_network_validator(BlockNumber(10))
        set_network_validators_checkpoint(CHAIN_HEAD_BLOCK)

        with _patch_consensus(
            _consensus_mock(builders=[builder_only])
        ) as consensus_mock, _patch_validators([]), mock.patch(
            'src.validators.builders_onboarding.validators_registry_contract.get_deposit_events',
            return_value=[],
        ) as events_mock:
            await resolve_builders_onboarding(_chain_head())

        assert consensus_mock.fork_head.await_args.args == (FORK_EPOCH,)
        events_mock.assert_awaited_once_with(from_block=FORK_BLOCK, to_block=CHAIN_HEAD_BLOCK)
        assert NetworkValidatorCrud().get_next_validator_index([]) == 0

    async def test_idempotent_when_transaction_fails(self):
        validator_key = faker.validator_public_key()
        _save_builder_deposits(validator_key)
        set_network_validators_checkpoint(CHAIN_HEAD_BLOCK)

        with _patch_consensus(), _patch_validators([validator_key]), mock.patch.object(
            BuilderDepositCrud, 'delete_all_builder_deposits', side_effect=RuntimeError
        ), pytest.raises(RuntimeError):
            await resolve_builders_onboarding(_chain_head())

        assert NetworkValidatorCrud().get_next_validator_index([]) == 0
        assert _builder_deposit_keys() == [validator_key]
        assert _onboarding_checkpoint() is None

        with _patch_consensus(), _patch_validators([validator_key]):
            await resolve_builders_onboarding(_chain_head())

        assert NetworkValidatorCrud().get_next_validator_index([]) == 1
        assert _builder_deposit_keys() == []
        assert _onboarding_checkpoint() == FORK_EPOCH


class TestResolveParity:
    async def test_old_and_fresh_databases_count_the_same_validators(self):
        """
        An old database saved all valid deposits as validators and removes the builders,
        a fresh one filters the builder deposits at the scan and adds the processed ones.
        """
        processed = faker.validator_public_key()
        pending_at_fork = faker.validator_public_key()
        builder_then_validator = faker.validator_public_key()
        regular = faker.validator_public_key()
        post_fork = faker.validator_public_key()
        events = [
            create_deposit_event(processed, b'\xb0', block_number=10),
            create_deposit_event(pending_at_fork, b'\xb0', block_number=11),
            create_deposit_event(builder_then_validator, b'\xb0', block_number=12),
            create_deposit_event(regular, b'\x01', block_number=13),
            create_deposit_event(post_fork, b'\xb0', block_number=950),
            create_deposit_event(builder_then_validator, b'\x01', block_number=951),
        ]
        post_fork_events = events[-2:]
        # The consensus layer processed all but the 0xB0 deposit pending at the fork
        head_validators = [processed, builder_then_validator, regular, post_fork]
        consensus_mock = _consensus_mock(builders=[pending_at_fork, builder_then_validator])
        all_public_keys = [processed, pending_at_fork, builder_then_validator, regular, post_fork]

        async def resolve(old_database: bool) -> tuple[int, set[HexStr]]:
            if old_database:
                NetworkValidatorCrud().save_network_validators(
                    [
                        NetworkValidator(
                            public_key=get_public_key(e), block_number=e['blockNumber']
                        )
                        for e in events
                    ]
                )
                set_network_validators_checkpoint(CHAIN_HEAD_BLOCK)
            else:
                _set_filter_marker()
                with mock.patch('src.validators.event_processors.ValidatorsRegistryContract'):
                    processor = NetworkValidatorsProcessor()
                with patch_deposit_signature(), patch_block_slot(
                    lambda block: FORK_SLOT - 1 if block < FORK_BLOCK else FORK_SLOT
                ):
                    await processor.process_events(events, CHAIN_HEAD_BLOCK)

            with _patch_consensus(consensus_mock), _patch_validators(
                head_validators
            ), patch_deposit_signature(), mock.patch(
                'src.validators.builders_onboarding.validators_registry_contract.get_deposit_events',
                return_value=post_fork_events,
            ):
                await resolve_builders_onboarding(_chain_head())

            crud = NetworkValidatorCrud()
            return crud.get_next_validator_index([]), crud.get_registered_public_keys(
                all_public_keys
            )

        old_result = await resolve(old_database=True)
        _reset_database()
        fresh_result = await resolve(old_database=False)

        assert old_result == fresh_result
        assert old_result == (4, {processed, builder_then_validator, regular, post_fork})


class TestFilterMarker:
    async def test_marked_when_database_is_empty(self):
        mark_fresh_network_validators()

        assert _filter_marker() == BUILDER_DEPOSITS_FILTER_APPLIED

    async def test_not_marked_when_validators_exist(self):
        save_network_validator(BlockNumber(1))

        mark_fresh_network_validators()

        assert _filter_marker() is None

    async def test_marker_is_not_dropped_by_later_validators(self):
        mark_fresh_network_validators()
        save_network_validator(BlockNumber(1))

        mark_fresh_network_validators()

        assert _filter_marker() == BUILDER_DEPOSITS_FILTER_APPLIED


class TestForkStateUnavailable:
    @pytest.mark.parametrize('status', [400, 404, 500, 503])
    async def test_rescans_network_validators_without_marker(self, status):
        stale_validator = save_network_validator(BlockNumber(10))
        stale_builder_deposit = faker.validator_public_key()
        rescanned_deposit = faker.validator_public_key()
        _save_builder_deposits(stale_builder_deposit)
        set_network_validators_checkpoint(CHAIN_HEAD_BLOCK)
        consensus_mock = _consensus_mock()
        consensus_mock.get_builders.side_effect = _response_error(status)

        async def rescan(block_number: BlockNumber, is_startup: bool) -> None:
            # The rescan finds a builder deposit that became a validator
            assert NetworkValidatorCrud().get_last_network_validator() is None
            assert _filter_marker() is not None
            assert (
                CheckpointCrud().get_checkpoint(CheckpointCrud.CHECKPOINT_NETWORK_VALIDATORS)
                is None
            )
            BuilderDepositCrud().save_builder_deposits(
                [BuilderDeposit(public_key=rescanned_deposit, block_number=BlockNumber(20))]
            )
            set_network_validators_checkpoint(block_number)

        with _patch_consensus(consensus_mock), _patch_validators([rescanned_deposit]), mock.patch(
            'src.validators.builders_onboarding.load_genesis_validators'
        ) as genesis_mock, mock.patch(
            'src.validators.builders_onboarding.scan_validators_events', side_effect=rescan
        ) as scan_mock:
            await resolve_builders_onboarding(_chain_head())

        genesis_mock.assert_awaited_once_with()
        scan_mock.assert_awaited_once_with(CHAIN_HEAD_BLOCK, is_startup=True)
        assert NetworkValidatorCrud().get_registered_public_keys(
            [stale_validator, stale_builder_deposit, rescanned_deposit]
        ) == {rescanned_deposit}
        assert _builder_deposit_keys() == []
        assert _onboarding_checkpoint() == FORK_EPOCH
        assert _filter_marker() is not None

    async def test_pending_deposits_state_unavailable(self):
        builder_only = save_network_validator(BlockNumber(10))
        set_network_validators_checkpoint(CHAIN_HEAD_BLOCK)
        consensus_mock = _consensus_mock(builders=[builder_only])
        consensus_mock.get_pending_deposits.side_effect = _response_error(404)

        with _patch_consensus(consensus_mock), _patch_validators([]), mock.patch(
            'src.validators.builders_onboarding.load_genesis_validators'
        ), mock.patch('src.validators.builders_onboarding.scan_validators_events') as scan_mock:
            await resolve_builders_onboarding(_chain_head())

        scan_mock.assert_awaited_once()
        assert NetworkValidatorCrud().get_last_network_validator() is None
        assert _filter_marker() is not None

    async def test_keeps_validators_with_marker(self):
        saved = save_network_validator(BlockNumber(10))
        _set_filter_marker()
        set_network_validators_checkpoint(CHAIN_HEAD_BLOCK)
        consensus_mock = _consensus_mock(builders=[saved])
        consensus_mock.get_builders.side_effect = _response_error(404)

        with _patch_consensus(consensus_mock), _patch_validators([]), mock.patch(
            'src.validators.builders_onboarding.scan_validators_events'
        ) as scan_mock:
            await resolve_builders_onboarding(_chain_head())

        scan_mock.assert_not_called()
        assert NetworkValidatorCrud().get_registered_public_keys([saved]) == {saved}
        assert _onboarding_checkpoint() == FORK_EPOCH

    async def test_other_errors_are_not_swallowed(self):
        saved = save_network_validator(BlockNumber(10))
        set_network_validators_checkpoint(CHAIN_HEAD_BLOCK)
        consensus_mock = _consensus_mock()
        consensus_mock.get_builders.side_effect = asyncio.TimeoutError()

        with _patch_consensus(consensus_mock), mock.patch(
            'src.validators.builders_onboarding.scan_validators_events'
        ) as scan_mock, pytest.raises(asyncio.TimeoutError):
            await resolve_builders_onboarding(_chain_head())

        scan_mock.assert_not_called()
        assert NetworkValidatorCrud().get_registered_public_keys([saved]) == {saved}
        assert _filter_marker() is None
        assert _onboarding_checkpoint() is None


class TestIsValidatorApprovalsBlocked:
    async def test_not_blocked_before_fork(self):
        with _patch_current_slot(FORK_SLOT - 1):
            assert not is_validator_approvals_blocked()

    async def test_blocked_by_saved_builder_deposit(self):
        _save_builder_deposits(faker.validator_public_key())

        with _patch_current_slot(FORK_SLOT - 1):
            assert is_validator_approvals_blocked()

    async def test_blocked_after_fork_until_resolved(self):
        with _patch_current_slot(FORK_SLOT):
            assert is_validator_approvals_blocked()

            CheckpointCrud().update_checkpoint(
                CheckpointCrud.CHECKPOINT_BUILDERS_ONBOARDING, FORK_EPOCH
            )
            assert not is_validator_approvals_blocked()


class TestGetValidatorsStartIndex:
    async def test_counts_tail_validators(self):
        save_network_validator(BlockNumber(5))
        event = create_deposit_event(withdrawal_credentials_prefix=b'\x01')

        with _patch_current_slot(FORK_SLOT - 1), patch_deposit_signature(), patch_tail_events(
            [event]
        ):
            assert await get_validators_start_index() == 2

    async def test_none_for_unsaved_builder_deposit(self):
        event = create_deposit_event(withdrawal_credentials_prefix=b'\xb0')

        with _patch_current_slot(FORK_SLOT - 1), patch_deposit_signature(), patch_block_slot(
            lambda _: FORK_SLOT - 1
        ), patch_tail_events([event]):
            assert await get_validators_start_index() is None

    async def test_none_while_blocked(self):
        with _patch_current_slot(FORK_SLOT), patch_tail_events([]) as events_mock:
            assert await get_validators_start_index() is None

        # One log request for both checks
        events_mock.assert_awaited_once()

    async def test_post_fork_builder_credentials_do_not_block(self):
        CheckpointCrud().update_checkpoint(
            CheckpointCrud.CHECKPOINT_BUILDERS_ONBOARDING, FORK_EPOCH
        )
        event = create_deposit_event(withdrawal_credentials_prefix=b'\xb0')

        with _patch_current_slot(FORK_SLOT + 10), patch_deposit_signature(), patch_block_slot(
            lambda _: FORK_SLOT + 1
        ), patch_tail_events([event]):
            assert await get_validators_start_index() == 1


class TestRegistrationGuard:
    async def test_register_new_validators_skipped_while_blocked(self, fake_settings):
        with mock.patch(
            'src.validators.tasks.is_validator_approvals_blocked', return_value=True
        ), mock.patch('src.validators.tasks.get_protocol_config') as protocol_config_mock:
            result = await register_new_validators(
                vault_assets=Gwei(100 * 10**9), harvest_params=None, keystore=None, relayer=None
            )

        assert result is None
        protocol_config_mock.assert_not_called()

    async def test_unknown_index_skips_the_cycle(self, fake_settings):
        with mock.patch(
            'src.validators.tasks._register_new_validators', side_effect=ValidatorIndexUnknownError
        ):
            result = await register_new_validators(
                vault_assets=Gwei(100 * 10**9), harvest_params=None, keystore=None, relayer=None
            )

        assert result is None

    async def test_index_recheck_returns_none_for_unknown_index(self, fake_settings):
        with mock.patch(
            'src.validators.tasks.get_validators_start_index', return_value=None
        ), mock.patch(
            'src.validators.tasks.validators_registry_contract.get_registry_root',
            return_value='0x01',
        ), mock.patch(
            'src.validators.tasks.tx_register_validators'
        ) as register_mock:
            result = await validate_index_and_register_validators(
                approval=MagicMock(),
                validators=[],
                harvest_params=None,
                validators_registry_root=HexStr('0x01'),
                validator_index=0,
                validators_manager_signature=HexStr('0x'),
            )

        assert result is None
        register_mock.assert_not_called()

    async def test_approval_request_not_created_for_unknown_index(self, fake_settings):
        with mock.patch(
            'src.validators.oracles.get_validators_start_index', return_value=None
        ), pytest.raises(ValidatorIndexUnknownError):
            await create_approval_request(
                protocol_config=MagicMock(),
                keystore=None,
                validators=[],
                registry_root=HexStr('0x01'),
                deadline=1,
                validators_manager_signature=HexStr('0x'),
            )

    async def test_relayer_is_not_called_for_unknown_index(self, fake_settings):
        with mock.patch(
            'src.validators.relayer.get_validators_start_index', return_value=None
        ), mock.patch.object(
            RelayerClient, '_register_validators', new_callable=AsyncMock
        ) as register_mock, pytest.raises(
            ValidatorIndexUnknownError
        ):
            await RelayerClient().register_validators(amounts=[Gwei(32 * 10**9)])

        register_mock.assert_not_called()


def _save_builder_deposits(*public_keys: HexStr) -> None:
    BuilderDepositCrud().save_builder_deposits(
        [
            BuilderDeposit(public_key=key, block_number=BlockNumber(10 + i))
            for i, key in enumerate(public_keys)
        ]
    )


def _builder_deposit_keys() -> list[HexStr]:
    return [d.public_key for d in BuilderDepositCrud().get_builder_deposits()]


def _onboarding_checkpoint() -> int | None:
    return CheckpointCrud().get_checkpoint(CheckpointCrud.CHECKPOINT_BUILDERS_ONBOARDING)


def _filter_marker() -> int | None:
    return CheckpointCrud().get_checkpoint(CheckpointCrud.CHECKPOINT_BUILDER_DEPOSITS_FILTER)


def _set_filter_marker() -> None:
    CheckpointCrud().update_checkpoint(
        CheckpointCrud.CHECKPOINT_BUILDER_DEPOSITS_FILTER, BUILDER_DEPOSITS_FILTER_APPLIED
    )


def _reset_database() -> None:
    NetworkValidatorCrud().delete_all_network_validators()
    BuilderDepositCrud().delete_all_builder_deposits()
    checkpoint_crud = CheckpointCrud()
    for name in (
        checkpoint_crud.CHECKPOINT_NETWORK_VALIDATORS,
        checkpoint_crud.CHECKPOINT_BUILDERS_ONBOARDING,
        checkpoint_crud.CHECKPOINT_BUILDER_DEPOSITS_FILTER,
    ):
        checkpoint_crud.delete_checkpoint(name)


def _chain_head(slot: int = FORK_SLOT + 10) -> ChainHead:
    return create_chain_head(slot=slot, block_number=CHAIN_HEAD_BLOCK)


def _response_error(status: int) -> ClientResponseError:
    return ClientResponseError(request_info=MagicMock(), history=(), status=status)


def _pending_deposit(public_key: HexStr, signature: str) -> dict:
    return {
        'pubkey': public_key,
        'withdrawal_credentials': '0x01' + '00' * 31,
        'amount': '32000000000',
        'signature': signature,
        'slot': '1',
    }


@contextmanager
def _patch_current_slot(slot: int) -> Iterator[None]:
    with mock.patch(
        'src.validators.builders_onboarding.calc_slot_by_block_timestamp', return_value=slot
    ):
        yield


@contextmanager
def _patch_consensus(consensus_mock: MagicMock | None = None) -> Iterator[MagicMock]:
    consensus_mock = consensus_mock or _consensus_mock()
    with mock.patch(
        'src.validators.builders_onboarding.consensus_client', consensus_mock
    ), mock.patch(
        'src.validators.builders_onboarding.get_chain_epoch_head', consensus_mock.fork_head
    ):
        yield consensus_mock


def _consensus_mock(
    builders: list[HexStr] | None = None, pending_deposits: list[dict] | None = None
) -> MagicMock:
    """The last pre-fork payload is the block before the fork block."""
    consensus_mock = MagicMock()
    consensus_mock.get_builders = AsyncMock(
        return_value=[
            {'index': str(i), 'status': 'active', 'builder': {'pubkey': key}}
            for i, key in enumerate(builders or [])
        ]
    )
    consensus_mock.get_pending_deposits = AsyncMock(return_value=pending_deposits or [])
    consensus_mock.fork_head = AsyncMock(
        return_value=create_chain_head(
            epoch=FORK_EPOCH, slot=FORK_SLOT, block_number=FORK_BLOCK - 1
        )
    )
    return consensus_mock


@contextmanager
def _patch_validators(public_keys: list[HexStr]) -> Iterator[AsyncMock]:
    with mock.patch(
        'src.validators.builders_onboarding.fetch_consensus_validators',
        return_value=[create_consensus_validator(public_key=key) for key in public_keys],
    ) as validators_mock:
        yield validators_mock
