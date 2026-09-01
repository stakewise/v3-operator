from unittest.mock import AsyncMock, MagicMock, patch

from eth_typing import BlockNumber
from web3 import Web3

from src.common.harvest import get_multiple_harvest_params

HARVEST_MODULE = 'src.common.harvest'

VAULT_1 = Web3.to_checksum_address('0x' + '11' * 20)
VAULT_2 = Web3.to_checksum_address('0x' + '22' * 20)
OWNER_1 = Web3.to_checksum_address('0x' + '33' * 20)
OWNER_2 = Web3.to_checksum_address('0x' + '44' * 20)


class TestGetMultipleHarvestParams:
    async def test_empty_vaults(self) -> None:
        result = await get_multiple_harvest_params([], BlockNumber(100))
        assert result == {}

    async def test_no_last_rewards(self) -> None:
        with patch(f'{HARVEST_MODULE}.keeper_contract') as mock_keeper:
            mock_keeper.get_last_rewards_update = AsyncMock(return_value=None)
            result = await get_multiple_harvest_params([VAULT_1], BlockNumber(100))
        assert result == {VAULT_1: None}

    async def test_cannot_harvest(self) -> None:
        mock_last_rewards = MagicMock()
        mock_last_rewards.ipfs_hash = 'QmTest'
        with (
            patch(f'{HARVEST_MODULE}.keeper_contract') as mock_keeper,
            patch(f'{HARVEST_MODULE}.ipfs_fetch_client') as mock_ipfs,
        ):
            mock_keeper.get_last_rewards_update = AsyncMock(return_value=mock_last_rewards)
            mock_keeper.can_harvest = AsyncMock(return_value=False)
            mock_ipfs.fetch_json = AsyncMock(return_value={})
            result = await get_multiple_harvest_params([VAULT_1, VAULT_2], BlockNumber(100))
        assert result == {VAULT_1: None, VAULT_2: None}
