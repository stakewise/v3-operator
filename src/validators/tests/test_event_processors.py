from multiprocessing.dummy import Pool as ThreadPool
from unittest import mock

import pytest
from eth_typing import BlockNumber
from sw_utils import FAR_FUTURE_EPOCH
from sw_utils.tests import faker

from src.config.networks import HOODI, NETWORKS
from src.config.settings import settings
from src.validators.database import (
    BuilderDepositCrud,
    CheckpointCrud,
    NetworkValidatorCrud,
)
from src.validators.event_processors import (
    NetworkValidatorsProcessor,
    NetworkValidatorsStartupProcessor,
    VaultV2ValidatorsProcessor,
    VaultValidatorsProcessor,
    get_latest_deposits,
    get_latest_vault_v2_validator_public_keys,
    get_network_validators_from_block,
    process_network_validator_events,
    process_network_validator_events_multiprocessing,
)
from src.validators.tests.factories import (
    FORK_SLOT,
    create_deposit_event,
    get_public_key,
    patch_block_slot,
    patch_deposit_signature,
    patch_tail_events,
    save_network_validator,
    set_network_validators_checkpoint,
)
from src.validators.typings import BuilderDeposit


@pytest.fixture
def vault_validators_processor(fake_settings) -> VaultValidatorsProcessor:
    with mock.patch('src.validators.event_processors.VaultContract'):
        return VaultValidatorsProcessor(settings.vault)


@pytest.fixture
def vault_v2_validators_processor(fake_settings) -> VaultV2ValidatorsProcessor:
    with mock.patch('src.validators.event_processors.VaultContract'):
        return VaultV2ValidatorsProcessor(settings.vault)


class TestVaultValidatorsProcessorFromBlock:
    async def test_uses_checkpoint(self, checkpoint_crud, vault_validators_processor):
        checkpoint_crud.update_validators_checkpoint(BlockNumber(3_500_000))

        assert await vault_validators_processor.get_from_block() == BlockNumber(3_500_001)

    async def test_zero_checkpoint_is_not_a_fallback(
        self, checkpoint_crud, vault_validators_processor
    ):
        checkpoint_crud.update_validators_checkpoint(BlockNumber(0))

        assert await vault_validators_processor.get_from_block() == BlockNumber(1)

    async def test_falls_back_to_keeper_genesis(self, checkpoint_crud, vault_validators_processor):
        keeper_genesis = NETWORKS[HOODI].KEEPER_GENESIS_BLOCK

        assert await vault_validators_processor.get_from_block() == keeper_genesis


class TestVaultV2ValidatorsProcessorFromBlock:
    async def test_uses_checkpoint(self, checkpoint_crud, vault_v2_validators_processor):
        checkpoint_crud.update_validators_checkpoint(BlockNumber(3_500_000))

        assert await vault_v2_validators_processor.get_from_block() == BlockNumber(3_500_001)

    async def test_falls_back_to_keeper_genesis(
        self, checkpoint_crud, vault_v2_validators_processor, monkeypatch
    ):
        keeper_genesis = NETWORKS[HOODI].KEEPER_GENESIS_BLOCK
        monkeypatch.setattr(NETWORKS[HOODI], 'PECTRA_BLOCK', BlockNumber(0))

        assert await vault_v2_validators_processor.get_from_block() == keeper_genesis

    async def test_falls_back_to_pectra_block(
        self, checkpoint_crud, vault_v2_validators_processor, monkeypatch
    ):
        pectra_block = BlockNumber(NETWORKS[HOODI].KEEPER_GENESIS_BLOCK + 1_000)
        monkeypatch.setattr(NETWORKS[HOODI], 'PECTRA_BLOCK', pectra_block)

        assert await vault_v2_validators_processor.get_from_block() == pectra_block


class TestGetLatestVaultV2ValidatorPublicKeys:
    async def test_uses_checkpoint(self, checkpoint_crud):
        checkpoint_crud.update_validators_checkpoint(BlockNumber(3_500_000))

        with mock.patch('src.validators.event_processors.VaultContract') as vault_contract:
            contract = vault_contract.return_value
            contract.get_v2_validator_registered_public_keys = mock.AsyncMock(return_value=[])
            await get_latest_vault_v2_validator_public_keys(settings.vault)

        contract.get_v2_validator_registered_public_keys.assert_awaited_once_with(
            from_block=BlockNumber(3_500_001)
        )

    async def test_falls_back_to_v2_genesis_block(self, checkpoint_crud, monkeypatch):
        pectra_block = BlockNumber(NETWORKS[HOODI].KEEPER_GENESIS_BLOCK + 1_000)
        monkeypatch.setattr(NETWORKS[HOODI], 'PECTRA_BLOCK', pectra_block)

        with mock.patch('src.validators.event_processors.VaultContract') as vault_contract:
            contract = vault_contract.return_value
            contract.get_v2_validator_registered_public_keys = mock.AsyncMock(return_value=[])
            await get_latest_vault_v2_validator_public_keys(settings.vault)

        contract.get_v2_validator_registered_public_keys.assert_awaited_once_with(
            from_block=pectra_block
        )


class TestGetNetworkValidatorsFromBlock:
    async def test_no_validators(self, validators_db):
        assert (
            await get_network_validators_from_block()
            == NETWORKS[HOODI].VALIDATORS_REGISTRY_GENESIS_BLOCK
        )

    async def test_fallback_to_last_validator(self, validators_db):
        last_block = NETWORKS[HOODI].CHECKPOINTS.GENESIS_VALIDATORS_LAST_BLOCK
        save_network_validator(BlockNumber(last_block + 10))

        assert await get_network_validators_from_block() == last_block + 11

    async def test_fallback_does_not_precede_genesis_validators_dump(self, validators_db):
        last_block = NETWORKS[HOODI].CHECKPOINTS.GENESIS_VALIDATORS_LAST_BLOCK
        save_network_validator(BlockNumber(last_block - 10))

        assert await get_network_validators_from_block() == last_block + 1

    async def test_checkpoint_wins_over_last_validator(self, validators_db):
        save_network_validator(BlockNumber(500))
        set_network_validators_checkpoint(BlockNumber(900))

        assert await get_network_validators_from_block() == BlockNumber(901)

    async def test_checkpoint_after_scan_without_validators(self, validators_db):
        to_block = BlockNumber(NETWORKS[HOODI].VALIDATORS_REGISTRY_GENESIS_BLOCK + 100)

        await _process_events([], to_block)

        assert await get_network_validators_from_block() == to_block + 1
        assert NetworkValidatorCrud().get_last_network_validator() is None


class TestProcessNetworkValidatorEvents:
    async def test_pre_fork_builder_deposit(self, validators_db, fork_epoch):
        validator_event = create_deposit_event(withdrawal_credentials_prefix=b'\x01')
        compounding_event = create_deposit_event(withdrawal_credentials_prefix=b'\x02')
        builder_event = create_deposit_event(withdrawal_credentials_prefix=b'\xb0')

        with patch_deposit_signature(), patch_block_slot(lambda _: FORK_SLOT - 1):
            validators, builder_deposits = await process_network_validator_events(
                [validator_event, compounding_event, builder_event]
            )

        assert [v.public_key for v in validators] == [
            get_public_key(validator_event),
            get_public_key(compounding_event),
        ]
        assert builder_deposits == [
            BuilderDeposit(
                public_key=get_public_key(builder_event),
                block_number=builder_event['blockNumber'],
            )
        ]

    async def test_post_fork_builder_credentials_are_validator(self, validators_db, fork_epoch):
        event = create_deposit_event(withdrawal_credentials_prefix=b'\xb0')

        with patch_deposit_signature(), patch_block_slot(lambda _: FORK_SLOT):
            validators, builder_deposits = await process_network_validator_events([event])

        assert [v.public_key for v in validators] == [get_public_key(event)]
        assert builder_deposits == []

    async def test_invalid_signature_is_skipped(self, validators_db, fork_epoch):
        events = [
            create_deposit_event(withdrawal_credentials_prefix=b'\x01'),
            create_deposit_event(withdrawal_credentials_prefix=b'\xb0'),
        ]
        with patch_deposit_signature(is_valid=False):
            assert await process_network_validator_events(events) == ([], [])

    async def test_batch_straddling_fork(self, validators_db, fork_epoch):
        before_fork = create_deposit_event(withdrawal_credentials_prefix=b'\xb0', block_number=10)
        after_fork = create_deposit_event(withdrawal_credentials_prefix=b'\xb0', block_number=11)
        slot_by_block = {10: FORK_SLOT - 1, 11: FORK_SLOT}

        with patch_deposit_signature(), patch_block_slot(lambda block: slot_by_block[block]):
            validators, builder_deposits = await process_network_validator_events(
                [before_fork, after_fork]
            )

        assert [d.public_key for d in builder_deposits] == [get_public_key(before_fork)]
        assert [v.public_key for v in validators] == [get_public_key(after_fork)]

    async def test_only_builder_credentials_fetch_block(self, validators_db, fork_epoch):
        events = [
            create_deposit_event(withdrawal_credentials_prefix=b'\x01'),
            create_deposit_event(withdrawal_credentials_prefix=b'\x02'),
        ]
        with patch_deposit_signature(), patch_block_slot(lambda _: 0) as slot_mock:
            validators, _ = await process_network_validator_events(events)

        assert len(validators) == 2
        slot_mock.assert_not_called()

    async def test_fork_not_scheduled_skips_block_fetch(self, validators_db, monkeypatch):
        monkeypatch.setattr(NETWORKS[HOODI], 'GLAMSTERDAM_EPOCH', FAR_FUTURE_EPOCH)
        event = create_deposit_event(withdrawal_credentials_prefix=b'\xb0')

        with patch_deposit_signature(), patch_block_slot(lambda _: 0) as slot_mock:
            validators, builder_deposits = await process_network_validator_events([event])

        assert validators == []
        assert len(builder_deposits) == 1
        slot_mock.assert_not_called()

    async def test_multiprocessing_splits_builder_deposits(self, validators_db, fork_epoch):
        validator_event = create_deposit_event(withdrawal_credentials_prefix=b'\x01')
        before_fork = create_deposit_event(withdrawal_credentials_prefix=b'\xb0', block_number=10)
        after_fork = create_deposit_event(withdrawal_credentials_prefix=b'\xb0', block_number=11)
        invalid = create_deposit_event(withdrawal_credentials_prefix=b'\xb0', block_number=10)
        slot_by_block = {10: FORK_SLOT - 1, 11: FORK_SLOT}
        events = [validator_event, before_fork, after_fork, invalid]

        # Worker threads share the patched module, worker processes would not
        with patch_deposit_signature(
            is_valid=lambda public_key, *_: public_key != invalid['args']['pubkey']
        ), patch_block_slot(lambda block: slot_by_block.get(block, 0)), mock.patch(
            'src.validators.event_processors.Pool', ThreadPool
        ):
            validators, builder_deposits = await process_network_validator_events_multiprocessing(
                events
            )

        assert [v.public_key for v in validators] == [
            get_public_key(validator_event),
            get_public_key(after_fork),
        ]
        assert [d.public_key for d in builder_deposits] == [get_public_key(before_fork)]


class TestNetworkValidatorsProcessor:
    @pytest.mark.parametrize(
        'processor_class', [NetworkValidatorsProcessor, NetworkValidatorsStartupProcessor]
    )
    async def test_saves_builder_deposits_separately(
        self, validators_db, fork_epoch, processor_class
    ):
        validator_event = create_deposit_event(withdrawal_credentials_prefix=b'\x01')
        builder_event = create_deposit_event(withdrawal_credentials_prefix=b'\xb0')
        to_block = BlockNumber(100_000)

        with mock.patch('src.validators.event_processors.Pool', ThreadPool):
            await _process_events([validator_event, builder_event], to_block, processor_class)

        crud = NetworkValidatorCrud()
        assert crud.get_next_validator_index([]) == 1
        assert crud.is_validator_registered(get_public_key(validator_event))
        assert not crud.is_validator_registered(get_public_key(builder_event))
        assert [d.public_key for d in BuilderDepositCrud().get_builder_deposits()] == [
            get_public_key(builder_event)
        ]
        assert await get_network_validators_from_block() == to_block + 1

    async def test_top_up_of_counted_public_key_is_dropped(self, validators_db, fork_epoch):
        registered = save_network_validator(BlockNumber(5))
        same_batch = faker.validator_public_key()
        events = [
            create_deposit_event(public_key=registered, withdrawal_credentials_prefix=b'\xb0'),
            create_deposit_event(public_key=same_batch, withdrawal_credentials_prefix=b'\x01'),
            create_deposit_event(public_key=same_batch, withdrawal_credentials_prefix=b'\xb0'),
        ]

        await _process_events(events, BlockNumber(100_000))

        assert NetworkValidatorCrud().get_next_validator_index([]) == 2
        assert BuilderDepositCrud().get_builder_deposits() == []

    async def test_saves_in_one_transaction(self, validators_db, fork_epoch):
        events = [
            create_deposit_event(withdrawal_credentials_prefix=b'\x01'),
            create_deposit_event(withdrawal_credentials_prefix=b'\xb0'),
        ]

        with mock.patch.object(
            CheckpointCrud, 'update_checkpoint', side_effect=RuntimeError
        ), pytest.raises(RuntimeError):
            await _process_events(events, BlockNumber(100_000))

        assert NetworkValidatorCrud().get_last_network_validator() is None
        assert BuilderDepositCrud().get_builder_deposits() == []


class TestGetLatestDeposits:
    async def test_tail_validators_and_builder_deposits(self, validators_db, fork_epoch):
        registered = save_network_validator(BlockNumber(5))
        set_network_validators_checkpoint(BlockNumber(900))
        validator_event = create_deposit_event(withdrawal_credentials_prefix=b'\x01')
        builder_event = create_deposit_event(withdrawal_credentials_prefix=b'\xb0')
        top_up_event = create_deposit_event(
            public_key=registered, withdrawal_credentials_prefix=b'\xb0'
        )

        with patch_deposit_signature(), patch_block_slot(
            lambda _: FORK_SLOT - 1
        ), patch_tail_events([validator_event, builder_event, top_up_event]) as events_mock:
            public_keys, builder_deposits = await get_latest_deposits()

        events_mock.assert_awaited_once_with(from_block=BlockNumber(901))
        assert public_keys == {get_public_key(validator_event)}
        assert [d.public_key for d in builder_deposits] == [get_public_key(builder_event)]

    async def test_tail_starts_after_last_validator_without_checkpoint(self, validators_db):
        last_block = NETWORKS[HOODI].CHECKPOINTS.GENESIS_VALIDATORS_LAST_BLOCK
        save_network_validator(BlockNumber(last_block + 500))

        with patch_tail_events([]) as events_mock:
            await get_latest_deposits()

        events_mock.assert_awaited_once_with(from_block=BlockNumber(last_block + 501))

    async def test_pre_fork_event_after_last_validator_is_not_reread(
        self, validators_db, fork_epoch
    ):
        """
        The last validator is before a pre-fork 0xB0 deposit that was resolved at the fork,
        the checkpoint keeps the deposit out of the tail.
        """
        save_network_validator(BlockNumber(500))
        set_network_validators_checkpoint(BlockNumber(1_000))

        with patch_tail_events([]) as events_mock:
            await get_latest_deposits()

        events_mock.assert_awaited_once_with(from_block=BlockNumber(1_001))


async def _process_events(
    events: list,
    to_block: BlockNumber,
    processor_class: type[NetworkValidatorsProcessor] = NetworkValidatorsProcessor,
) -> None:
    with mock.patch('src.validators.event_processors.ValidatorsRegistryContract'):
        processor = processor_class()
    with patch_deposit_signature(), patch_block_slot(lambda _: FORK_SLOT - 1):
        await processor.process_events(events, to_block)
