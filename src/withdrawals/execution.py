from sw_utils import convert_to_mgno
from sw_utils.networks import GNO_NETWORKS
from web3 import Web3
from web3.types import ChecksumAddress, Wei

from src.common.contracts import VaultContract, multicall_contract
from src.common.typings import HarvestParams
from src.config.settings import settings
from src.harvest.execution import get_update_state_calls


async def get_vault_assets(
    vault_address: ChecksumAddress,
    harvest_params: HarvestParams | None,
) -> tuple[Wei, Wei]:
    vault_contract = VaultContract(vault_address)

    if harvest_params is not None:
        # add update state calls before validator registration
        calls = await get_update_state_calls(
            vault_address=vault_address, harvest_params=harvest_params
        )
    else:
        # aggregate all the calls into one multicall
        calls = []
    calls.extend(
        [
            (vault_address, vault_contract.encode_abi('totalAssets')),
            (vault_address, vault_contract.encode_abi('getExitQueueData')),
        ]
    )
    _, multicall = await multicall_contract.aggregate(calls)
    queued_shares = Web3.to_int(multicall[-1][0])
    total_assets = Wei(Web3.to_int(multicall[-2][0]))

    queued_assets = await _convert_shares_to_assets(
        shares=queued_shares,
        vault_address=vault_address,
        harvest_params=harvest_params,
    )

    if settings.network in GNO_NETWORKS:
        return convert_to_mgno(Wei(queued_assets)), convert_to_mgno(Wei(total_assets))

    return queued_assets, total_assets


async def _convert_shares_to_assets(
    shares: int,
    vault_address: ChecksumAddress,
    harvest_params: HarvestParams | None,
) -> Wei:

    vault_contract = VaultContract(vault_address)
    if harvest_params is not None:
        # add update state calls before validator registration
        calls = await get_update_state_calls(
            vault_address=vault_address, harvest_params=harvest_params
        )
    else:
        # aggregate all the calls into one multicall
        calls = []
    calls.append((vault_address, vault_contract.encode_abi('convertToAssets', args=[shares])))

    _, multicall = await multicall_contract.aggregate(calls)
    return Wei(Web3.to_int(multicall[-1]))
