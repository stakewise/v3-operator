from unittest import mock
from unittest.mock import AsyncMock

import pytest

from src.exits.consensus import get_validator_public_keys


@pytest.mark.usefixtures('fake_settings')
class TestGetValidatorPublicKeys:
    async def test_keeps_only_requested_indexes(self):
        # The consensus client returns a requested index (10) plus an unrequested one (999);
        # the unrequested record must not end up in the index-to-public-key mapping.
        response = {
            'data': [
                {'index': '10', 'validator': {'pubkey': '0xaa'}},
                {'index': '999', 'validator': {'pubkey': '0xbb'}},
            ]
        }
        with mock.patch('src.exits.consensus.consensus_client', new=AsyncMock()) as consensus_mock:
            consensus_mock.get_validators_by_ids.return_value = response
            result = await get_validator_public_keys([10])

        assert result == {10: '0xaa'}
        consensus_mock.get_validators_by_ids.assert_called_once_with(['10'], state_id='finalized')
