from unittest import mock

from eth_abi import abi as eth_abi
from hexbytes import HexBytes
from web3 import AsyncWeb3, Web3
from web3.types import BlockNumber, Wei

from src.common.contracts import VaultContract
from src.common.typings import HarvestParams

VAULT_ADDRESS = Web3.to_checksum_address('0x' + '11' * 20)


class TestGetQueuedExitAssets:
    async def test_without_harvest_params(self):
        vault = _vault_contract()
        exit_queue_data = eth_abi.encode(
            ['uint128', 'uint128', 'uint128', 'uint128', 'uint256'], [10, 1, 2, 3, 4]
        )
        response = [exit_queue_data, (25).to_bytes(32, 'big'), (100).to_bytes(32, 'big')]

        with mock.patch.object(vault.contract.functions, 'multicall') as multicall_mock:
            multicall_mock.return_value.call = mock.AsyncMock(return_value=response)
            result = await vault.get_queued_exit_assets(None, BlockNumber(123))

        assert result == Wei(2)  # 10 * 25 // 100
        multicall_mock.return_value.call.assert_awaited_once_with(block_identifier=BlockNumber(123))
        assert len(multicall_mock.call_args.args[0]) == 3

    async def test_with_harvest_params(self):
        vault = _vault_contract()
        harvest_params = HarvestParams(
            rewards_root=HexBytes(b'\x00' * 32),
            reward=Wei(0),
            unlocked_mev_reward=Wei(0),
            proof=[],
        )
        exit_queue_data = eth_abi.encode(
            ['uint128', 'uint128', 'uint128', 'uint128', 'uint256'], [10, 1, 2, 3, 4]
        )
        response = [b'', exit_queue_data, (25).to_bytes(32, 'big'), (100).to_bytes(32, 'big')]

        with mock.patch.object(vault.contract.functions, 'multicall') as multicall_mock:
            multicall_mock.return_value.call = mock.AsyncMock(return_value=response)
            result = await vault.get_queued_exit_assets(harvest_params, BlockNumber(123))

        assert result == Wei(2)  # 10 * 25 // 100
        assert len(multicall_mock.call_args.args[0]) == 4

    async def test_zero_total_shares(self):
        vault = _vault_contract()
        exit_queue_data = eth_abi.encode(
            ['uint128', 'uint128', 'uint128', 'uint128', 'uint256'], [10, 1, 2, 3, 4]
        )
        response = [exit_queue_data, (0).to_bytes(32, 'big'), (0).to_bytes(32, 'big')]

        with mock.patch.object(vault.contract.functions, 'multicall') as multicall_mock:
            multicall_mock.return_value.call = mock.AsyncMock(return_value=response)
            result = await vault.get_queued_exit_assets(None, BlockNumber(123))

        assert result == Wei(0)


def _vault_contract() -> VaultContract:
    # A bare AsyncWeb3() avoids hitting the not-set-up ``execution_client`` singleton;
    # eth.contract() only builds a local contract object, no network call is made.
    return VaultContract(address=VAULT_ADDRESS, execution_client=AsyncWeb3())
