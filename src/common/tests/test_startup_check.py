from typing import Generator
from unittest import mock

import pytest
from eth_typing import BlockNumber
from sw_utils.tests import faker

from src.common.startup_check import check_db_events_logs, check_events_logs
from src.config.settings import settings
from src.validators.database import NetworkValidatorCrud
from src.validators.typings import NetworkValidator


@pytest.fixture
def mocked_get_logs() -> Generator[mock.AsyncMock, None, None]:
    with mock.patch(
        'src.common.startup_check.validators_registry_contract.events.DepositEvent.get_logs',
        new_callable=mock.AsyncMock,
    ) as get_logs:
        yield get_logs


@pytest.fixture
def network_validator_crud(fake_settings) -> Generator[NetworkValidatorCrud, None, None]:
    crud = NetworkValidatorCrud()
    crud.setup()
    yield crud
    settings.database.unlink(missing_ok=True)


@pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
class TestCheckEventsLogs:
    async def test_probes_genesis_validators_last_block(self, mocked_get_logs: mock.AsyncMock):
        mocked_get_logs.return_value = [{'event': 'DepositEvent'}]

        await check_events_logs()

        genesis_block = settings.network_config.CHECKPOINTS.GENESIS_VALIDATORS_LAST_BLOCK
        mocked_get_logs.assert_awaited_once_with(from_block=genesis_block, to_block=genesis_block)

    async def test_raises_on_pruned_logs(self, mocked_get_logs: mock.AsyncMock):
        mocked_get_logs.return_value = []

        with pytest.raises(ValueError, match="didn't prune event logs"):
            await check_events_logs()


@pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
class TestCheckDbEventsLogs:
    async def test_skips_empty_db(
        self, network_validator_crud: NetworkValidatorCrud, mocked_get_logs: mock.AsyncMock
    ):
        await check_db_events_logs()

        mocked_get_logs.assert_not_awaited()

    async def test_probes_last_network_validator_block(
        self, network_validator_crud: NetworkValidatorCrud, mocked_get_logs: mock.AsyncMock
    ):
        network_validator_crud.save_network_validators(
            [
                NetworkValidator(
                    public_key=faker.validator_public_key(), block_number=BlockNumber(100)
                ),
                NetworkValidator(
                    public_key=faker.validator_public_key(), block_number=BlockNumber(250)
                ),
            ]
        )
        mocked_get_logs.return_value = [{'event': 'DepositEvent'}]

        await check_db_events_logs()

        mocked_get_logs.assert_awaited_once_with(
            from_block=BlockNumber(250), to_block=BlockNumber(250)
        )

    async def test_raises_on_pruned_logs(
        self, network_validator_crud: NetworkValidatorCrud, mocked_get_logs: mock.AsyncMock
    ):
        network_validator_crud.save_network_validators(
            [
                NetworkValidator(
                    public_key=faker.validator_public_key(), block_number=BlockNumber(250)
                ),
            ]
        )
        mocked_get_logs.return_value = []

        with pytest.raises(ValueError, match='at block 250'):
            await check_db_events_logs()
