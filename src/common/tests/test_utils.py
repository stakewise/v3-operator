import logging
from decimal import Decimal
from unittest.mock import patch

import pytest

from src.common.utils import error_verbose, round_down


def test_round_down():
    assert round_down(100, 2) == Decimal('100.00')
    assert round_down(Decimal('100.123'), 2) == Decimal('100.12')
    assert round_down(Decimal('100.999'), 2) == Decimal('100.99')


@pytest.mark.parametrize('verbose', [True, False])
def test_error_verbose_keeps_message(verbose: bool, caplog: pytest.LogCaptureFixture) -> None:
    """The message and its args survive in both modes; only the traceback differs."""
    with patch('src.common.utils.settings') as mock_settings:
        mock_settings.verbose = verbose
        with caplog.at_level(logging.ERROR, logger='src.common.utils'):
            try:
                raise ValueError('boom')
            except ValueError:
                error_verbose('Failed to process vault %s', '0xabc')

    record = caplog.records[0]
    assert record.getMessage() == 'Failed to process vault 0xabc'
    # Traceback is attached only in verbose mode
    assert (record.exc_info is not None) is verbose
