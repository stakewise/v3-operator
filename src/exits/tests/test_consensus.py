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
                _beacon_validator(index='10', pubkey='0xaa'),
                _beacon_validator(index='999', pubkey='0xbb'),
            ]
        }
        with mock.patch(
            'src.validators.consensus.consensus_client', new=AsyncMock()
        ) as consensus_mock:
            consensus_mock.get_validators_by_ids.return_value = response
            result = await get_validator_public_keys([10])

        assert result == {10: '0xaa'}
        consensus_mock.get_validators_by_ids.assert_called_once_with(
            validator_ids=('10',), state_id='finalized'
        )


def _beacon_validator(index: str, pubkey: str) -> dict:
    return {
        'index': index,
        'balance': '32000000000',
        'status': 'active_ongoing',
        'validator': {
            'pubkey': pubkey,
            'withdrawal_credentials': '0x01',
            'activation_epoch': '0',
        },
    }
