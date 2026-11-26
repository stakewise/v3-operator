from unittest import mock
from unittest.mock import AsyncMock, MagicMock

from prometheus_client import REGISTRY

from src.commands.start.base import ValidatorTask
from src.common.tests.factories import create_chain_head
from src.config.settings import settings


class TestValidatorTask:
    async def test_subtasks_run_when_builders_onboarding_fails(self, fake_settings):
        task = ValidatorTask(keystore=None, relayer=None)
        task.validator_registration_subtask = MagicMock(process=AsyncMock())
        task.validator_withdrawal_subtask = MagicMock(process=AsyncMock())
        exception_count = _exception_count()

        with mock.patch(
            'src.commands.start.base.get_chain_finalized_head',
            return_value=create_chain_head(),
        ), mock.patch('src.commands.start.base.scan_validators_events'), mock.patch(
            'src.commands.start.base.resolve_builders_onboarding', side_effect=RuntimeError('boom')
        ), mock.patch(
            'src.commands.start.base.log_verbose'
        ) as log_verbose:
            await task.process_block(MagicMock())

        log_verbose.assert_called_once()
        task.validator_registration_subtask.process.assert_awaited_once()
        task.validator_withdrawal_subtask.process.assert_awaited_once()
        assert _exception_count() == exception_count + 1


def _exception_count() -> float:
    value = REGISTRY.get_sample_value(
        f'{settings.metrics_prefix}_exception_count_total', {'network': settings.network}
    )
    return value or 0.0
