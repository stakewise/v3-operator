import pytest

from src.config.settings import settings
from src.validators.database import (
    CheckpointCrud,
    NetworkValidatorCrud,
    VaultValidatorCrud,
)


@pytest.fixture
def network_validator_crud(fake_settings):
    crud = NetworkValidatorCrud()
    crud.setup()
    yield crud
    settings.database.unlink(missing_ok=True)


@pytest.fixture
def checkpoint_crud(fake_settings):
    crud = CheckpointCrud()
    crud.setup()
    yield crud
    settings.database.unlink(missing_ok=True)


@pytest.fixture
def checkpoint_crud_no_setup(fake_settings):
    yield CheckpointCrud()
    settings.database.unlink(missing_ok=True)


@pytest.fixture
def vault_validator_crud(fake_settings):
    crud = VaultValidatorCrud()
    crud.setup()
    yield crud
    settings.database.unlink(missing_ok=True)


@pytest.fixture
def compounding_creds(fake_settings) -> str:
    return '0x02' + '00' * 11 + settings.vault[2:].lower()
