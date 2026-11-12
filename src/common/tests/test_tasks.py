import logging
from unittest import mock

import pytest
from prometheus_client import REGISTRY
from sw_utils import ExecutionBehindConsensusError, InterruptHandler

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
    async def test_execution_behind_consensus_is_skipped_with_warning(
        self, caplog: pytest.LogCaptureFixture
    ):
        task = _FailingTask(ExecutionBehindConsensusError('block is not available'))
        exception_count = _exception_count()

        with caplog.at_level(logging.WARNING, logger='src.common.tasks'):
            await task.run(InterruptHandler())

        task.process_block_mock.assert_awaited_once()
        assert _exception_count() == exception_count
        records = [r for r in caplog.records if r.name == 'src.common.tasks']
        assert len(records) == 1
        assert records[0].levelno == logging.WARNING
        assert 'block is not available' in records[0].getMessage()
        assert records[0].exc_info is None

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
