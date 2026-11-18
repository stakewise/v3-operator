from unittest import mock

import pytest
from prometheus_client import REGISTRY
from sw_utils import InterruptHandler

from src.common.tasks import BaseTask
from src.config.settings import settings


class _FailingTask(BaseTask):
    def __init__(self, error: Exception) -> None:
        self.error = error
        self.process_block_mock = mock.AsyncMock()

    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        await self.process_block_mock()
        interrupt_handler.exit = True
        raise self.error


@pytest.mark.usefixtures('fake_settings')
class TestBaseTaskRun:
    async def test_other_errors_are_counted(self):
        task = _FailingTask(RuntimeError('boom'))
        exception_count = _exception_count()

        with mock.patch('src.common.tasks.log_verbose') as log_verbose:
            await task.run(InterruptHandler())

        log_verbose.assert_called_once_with(task.error)
        assert _exception_count() == exception_count + 1


def _exception_count() -> float:
    value = REGISTRY.get_sample_value(
        f'{settings.metrics_prefix}_exception_count_total', {'network': settings.network}
    )
    return value or 0.0
