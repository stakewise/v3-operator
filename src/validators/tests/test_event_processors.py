from unittest import mock

import pytest
from eth_typing import BlockNumber

from src.config.networks import HOODI, NETWORKS
from src.config.settings import settings
from src.validators.event_processors import (
    VaultV2ValidatorsProcessor,
    VaultValidatorsProcessor,
    get_latest_vault_v2_validator_public_keys,
)


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
