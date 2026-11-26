import pytest

from src.config.networks import HOODI, NETWORKS
from src.config.settings import settings
from src.validators.database import (
    BuilderDepositCrud,
    CheckpointCrud,
    NetworkValidatorCrud,
    VaultValidatorCrud,
)
from src.validators.tests.factories import FORK_EPOCH


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
def builder_deposit_crud(fake_settings):
    crud = BuilderDepositCrud()
    crud.setup()
    yield crud
    settings.database.unlink(missing_ok=True)


@pytest.fixture
def validators_db(fake_settings):
    """Network validators, builder deposits and checkpoints tables."""
    NetworkValidatorCrud().setup()
    BuilderDepositCrud().setup()
    CheckpointCrud().setup()
    yield
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


@pytest.fixture
def fork_epoch(monkeypatch) -> int:
    """Schedules Glamsterdam at `FORK_EPOCH`."""
    monkeypatch.setattr(NETWORKS[HOODI], 'GLAMSTERDAM_EPOCH', FORK_EPOCH)
    return FORK_EPOCH
