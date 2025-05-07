from eth_typing import BlockNumber, HexStr
from sw_utils import convert_to_mgno
from sw_utils.networks import ETH_NETWORKS, GNO_NETWORKS
from web3 import Web3
from web3.exceptions import ContractLogicError
from web3.types import ChecksumAddress, Wei

from src.common.clients import execution_client
from src.common.contracts import (
    VaultContract,
    VaultErc20Contract,
    gno_erc20_contract,
    keeper_contract,
    multicall_contract,
    validators_registry_contract,
)
from src.common.typings import HarvestParams
from src.config.settings import settings

# https://github.com/stakewise/v3-core/blob/main/.openzeppelin/mainnet.json#L933
ERC20_VAULT_UNCLAIMED_ASSETS_STORAGE_POSITION = 208
# https://github.com/stakewise/v3-core/blob/main/.openzeppelin/mainnet.json#L85
VAULT_UNCLAIMED_ASSETS_STORAGE_POSITION = 153


# pylint: disable=too-many-statements
# pylint: disable=too-many-branches
# pylint: disable=too-many-locals
async def get_vault_assets(
    vault: ChecksumAddress,
    block_number: BlockNumber,
    harvest_params: HarvestParams | None,
) -> tuple[Wei, Wei]:
    vault_contract = VaultContract(vault)
    vault_erc20_contract = VaultErc20Contract(vault)
    # calculate storage position based on the type of the vault
    try:
        await vault_erc20_contract.symbol()
        storage_position = ERC20_VAULT_UNCLAIMED_ASSETS_STORAGE_POSITION
    except (ValueError, ContractLogicError):
        storage_position = VAULT_UNCLAIMED_ASSETS_STORAGE_POSITION

    # there is no way we can fetch unclaimed assets directly
    # from the contract as it's private variable, so we fetch through storage slot
    contract_slot = await execution_client.eth.get_storage_at(
        account=vault_contract.address, position=storage_position, block_identifier=block_number
    )
    # queued shares and unclaimed assets are stored as uint128,
    # so first 16 bytes are for queued shares and next 16 bytes for the unclaimed assets
    # NB! must be updated on vault storage layout change
    queued_shares_before = Web3.to_int(contract_slot[16:])
    unclaimed_assets = Web3.to_int(contract_slot[:16])

    is_genesis_vault = vault == settings.network_config.GENESIS_VAULT_CONTRACT_ADDRESS

    # define calls
    update_state_call = None
    if harvest_params and await keeper_contract.can_harvest(vault):
        update_state_call = (
            vault,
            _encode_update_state_call(
                vault_contract,
                harvest_params,
            ),
        )

    queued_shares_call = vault_contract.encode_abi('queuedShares')
    total_assets_call = vault_contract.encode_abi('totalAssets')
    calls = [
        (vault, queued_shares_call),
        (vault, total_assets_call),
        _get_encoded_balance_call(vault),
    ]

    if update_state_call:
        calls.insert(0, update_state_call)

    # add total exiting assets call for vaults with version >= 2
    vault_version = await vault_contract.version()
    if vault_version >= 2:
        calls.append((vault, vault_contract.encode_abi('totalExitingAssets')))

    if is_genesis_vault:
        # add balance from the pool escrow where validator withdrawals are done
        calls.append(
            _get_encoded_balance_call(settings.network_config.V2_POOL_ESCROW_CONTRACT_ADDRESS)
        )

    if settings.network in GNO_NETWORKS:
        # in GNO networks we have to pull partial and full withdrawals from the Gnosis contract
        calls.append(_get_encoded_gnosis_withdrawable_assets_call(vault))
        if is_genesis_vault:
            calls.append(
                _get_encoded_gnosis_withdrawable_assets_call(
                    settings.network_config.V2_POOL_ESCROW_CONTRACT_ADDRESS
                )
            )

    # fetch data
    _, response = await multicall_contract.aggregate(calls, block_number)
    if update_state_call:
        response.pop(0)

    queued_shares_after = Web3.to_int(response.pop(0))
    total_assets = Web3.to_int(response.pop(0))
    balance = Web3.to_int(response.pop(0))

    queued_assets = 0
    if vault_version >= 2:
        queued_assets = Web3.to_int(response.pop(0))
        # v2 vault exiting assets are excluded from the total assets of the vault
        total_assets += queued_assets

    if queued_shares_after <= 1 and queued_assets == 0:
        # nothing is queueing, return
        return Wei(0), Wei(total_assets)

    if is_genesis_vault:
        balance += Web3.to_int(response.pop(0))

    if settings.network in GNO_NETWORKS:
        balance += Web3.to_int(response.pop(0))
        if is_genesis_vault:
            balance += Web3.to_int(response.pop(0))

    # calculate exited shares
    exited_shares = queued_shares_before - queued_shares_after

    # convert exited and queued shares to assets
    exited_assets_call = vault_contract.encode_abi('convertToAssets', [exited_shares])
    queued_assets_call = vault_contract.encode_abi('convertToAssets', [queued_shares_after])
    calls = [
        (vault, exited_assets_call),
        (vault, queued_assets_call),
    ]

    if update_state_call:
        calls.insert(0, update_state_call)

    _, response = await multicall_contract.aggregate(calls, block_number)
    if update_state_call:
        response.pop(0)

    exited_assets = Web3.to_int(response[0])
    queued_assets += Web3.to_int(response[1])

    # calculate ETH balance without unclaimed assets
    # and assets that will exit during state update call
    balance -= unclaimed_assets
    balance -= exited_assets
    # calculate queued assets after all floating ETH is deducted
    queued_assets = max(0, queued_assets - balance)

    if settings.network in GNO_NETWORKS:
        return convert_to_mgno(Wei(queued_assets)), convert_to_mgno(Wei(total_assets))

    return Wei(queued_assets), Wei(total_assets)


def _get_encoded_balance_call(address: ChecksumAddress) -> tuple[ChecksumAddress, HexStr]:
    """Encodes the call to get the balance of the address."""
    if settings.network in ETH_NETWORKS:
        eth_balance_call = multicall_contract.encode_abi('getEthBalance', [address])
        return multicall_contract.address, eth_balance_call

    gno_addr = settings.network_config.GNO_TOKEN_CONTRACT_ADDRESS
    return gno_addr, gno_erc20_contract.encode_abi('balanceOf', [address])


def _get_encoded_gnosis_withdrawable_assets_call(
    address: ChecksumAddress,
) -> tuple[ChecksumAddress, HexStr]:
    """Encodes the call to get the validators registry withdrawable amount."""
    return (
        validators_registry_contract.address,
        validators_registry_contract.encode_abi('withdrawableAmount', [address]),
    )


def _encode_update_state_call(
    vault_contract: VaultContract, harvest_params: HarvestParams
) -> HexStr:
    return vault_contract.encode_abi(
        fn_name='updateState',
        args=[
            (
                harvest_params.rewards_root,
                harvest_params.reward,
                harvest_params.unlocked_mev_reward,
                harvest_params.proof,
            )
        ],
    )
