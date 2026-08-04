from unittest.mock import AsyncMock, patch

from sw_utils.tests import faker

from src.common.tests.utils import ether_to_gwei
from src.validators.consensus import fetch_pending_deposits_amounts


async def test_fetch_pending_deposits_amounts_empty_public_keys():
    """No pubkeys requested means no beacon call and an empty result."""
    mock_consensus = AsyncMock()

    with patch('src.validators.consensus.consensus_client', mock_consensus):
        result = await fetch_pending_deposits_amounts(public_keys=set(), slot='100')

    assert result == {}
    mock_consensus.get_pending_deposits.assert_not_called()


async def test_fetch_pending_deposits_amounts_sums_multiple_deposits():
    """Multiple pending deposits for the same pubkey are summed."""
    pub_key = faker.validator_public_key()

    mock_consensus = AsyncMock()
    mock_consensus.get_pending_deposits.return_value = [
        {
            'pubkey': pub_key,
            'amount': str(ether_to_gwei(1000)),
            'withdrawal_credentials': '0x02' + '00' * 30,
            'slot': '90',
        },
        {
            'pubkey': pub_key,
            'amount': str(ether_to_gwei(800)),
            'withdrawal_credentials': '0x02' + '00' * 30,
            'slot': '95',
        },
    ]

    with patch('src.validators.consensus.consensus_client', mock_consensus):
        result = await fetch_pending_deposits_amounts(public_keys={pub_key}, slot='100')

    assert result == {pub_key: ether_to_gwei(1800)}
    mock_consensus.get_pending_deposits.assert_called_once_with('100')


async def test_fetch_pending_deposits_amounts_filters_by_requested_public_keys():
    """Deposits for pubkeys outside the requested set are ignored."""
    requested_pub_key = faker.validator_public_key()
    other_pub_key = faker.validator_public_key()

    mock_consensus = AsyncMock()
    mock_consensus.get_pending_deposits.return_value = [
        {
            'pubkey': requested_pub_key,
            'amount': str(ether_to_gwei(32)),
            'withdrawal_credentials': '0x02' + '00' * 30,
            'slot': '90',
        },
        {
            'pubkey': other_pub_key,
            'amount': str(ether_to_gwei(9999)),
            'withdrawal_credentials': '0x02' + '00' * 30,
            'slot': '91',
        },
    ]

    with patch('src.validators.consensus.consensus_client', mock_consensus):
        result = await fetch_pending_deposits_amounts(public_keys={requested_pub_key}, slot='100')

    assert result == {requested_pub_key: ether_to_gwei(32)}


async def test_fetch_pending_deposits_amounts_counts_regardless_of_credentials_prefix():
    """Unlike funding balances, every pending deposit counts, not only 0x02-prefixed ones."""
    pub_key = faker.validator_public_key()

    mock_consensus = AsyncMock()
    mock_consensus.get_pending_deposits.return_value = [
        {
            'pubkey': pub_key,
            'amount': str(ether_to_gwei(10)),
            'withdrawal_credentials': '0x01' + '00' * 30,
            'slot': '90',
        },
        {
            'pubkey': pub_key,
            'amount': str(ether_to_gwei(20)),
            'withdrawal_credentials': '0x02' + '00' * 30,
            'slot': '91',
        },
    ]

    with patch('src.validators.consensus.consensus_client', mock_consensus):
        result = await fetch_pending_deposits_amounts(public_keys={pub_key}, slot='100')

    assert result == {pub_key: ether_to_gwei(30)}
