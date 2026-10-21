from dataclasses import asdict, dataclass

from eth_typing import BlockNumber, ChecksumAddress
from sw_utils.networks import CHIADO, GNOSIS, HOODI, MAINNET
from sw_utils.networks import NETWORKS as BASE_NETWORKS
from sw_utils.networks import BaseNetworkConfig
from web3 import Web3
from web3.types import Gwei, Wei

AVAILABLE_NETWORKS = [MAINNET, HOODI, GNOSIS, CHIADO]
RATED_NETWORKS = [MAINNET]


@dataclass
class CheckpointsConfig:
    """
    Pinned points past which the operator does not need execution client event logs.
    """

    # `ConfigUpdated` scans on a cold cache start from `CONFIG_UPDATE_CHECKPOINT_BLOCK + 1`.
    CONFIG_UPDATE_CHECKPOINT_BLOCK: BlockNumber
    # IPFS hash from the newest `ConfigUpdated` event before the checkpoint.
    # Lets the operator skip reading that event, which may be pruned from the node.
    CONFIG_UPDATE_LAST_EVENT_IPFS_HASH: str
    # `ExitSignaturesUpdated` scans on a cold cache start from
    # `EXIT_SIGNATURES_CHECKPOINT_BLOCK + 1`. Older rotations are long finalized
    # and already synced by oracles, so they don't gate a new rotation.
    EXIT_SIGNATURES_CHECKPOINT_BLOCK: BlockNumber
    # Network-wide dump of all vaults' `ValidatorRegistered` / `V2ValidatorRegistered`
    # events up to `VAULT_VALIDATORS_LAST_BLOCK`.
    VAULT_VALIDATORS_IPFS_HASH: str
    VAULT_VALIDATORS_LAST_BLOCK: BlockNumber


@dataclass
# pylint: disable-next=too-many-instance-attributes
class NetworkConfig(BaseNetworkConfig):
    WALLET_BALANCE_SYMBOL: str
    VAULT_BALANCE_SYMBOL: str
    DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS: ChecksumAddress
    HOT_WALLET_MIN_BALANCE: Wei
    STAKEWISE_API_URL: str
    RATED_API_URL: str
    DEFAULT_DVT_RELAYER_ENDPOINT: str
    MAX_FEE_PER_GAS_GWEI: Gwei
    CHECKPOINTS: CheckpointsConfig


def _base_config(network: str, **overrides: str | BlockNumber) -> dict:
    """
    Returns sw-utils network config as a dict with fields replaced by `overrides`.
    Used to pin newer genesis validators dumps than the ones shipped with sw-utils.
    """
    config = asdict(BASE_NETWORKS[network])
    for key, value in overrides.items():
        if key not in config:
            raise KeyError(f'Unknown network config field: {key}')
        config[key] = value
    return config


NETWORKS: dict[str, NetworkConfig] = {
    MAINNET: NetworkConfig(
        **_base_config(
            MAINNET,
            GENESIS_VALIDATORS_IPFS_HASH=(
                'bafybeigp2oamkahzc6g2juy3wsuknlyj2m4f27vma276d4bg5z7d64rvue'
            ),
            GENESIS_VALIDATORS_LAST_BLOCK=BlockNumber(25933938),
        ),
        WALLET_BALANCE_SYMBOL='ETH',
        VAULT_BALANCE_SYMBOL='ETH',
        DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x75AB6DdCe07556639333d3Df1eaa684F5735223e'
        ),
        HOT_WALLET_MIN_BALANCE=Web3.to_wei('0.03', 'ether'),
        STAKEWISE_API_URL='https://mainnet-api.stakewise.io/graphql',
        RATED_API_URL='https://api.rated.network',
        DEFAULT_DVT_RELAYER_ENDPOINT='https://mainnet-dvt-relayer.stakewise.io',
        MAX_FEE_PER_GAS_GWEI=Gwei(10),
        CHECKPOINTS=CheckpointsConfig(
            CONFIG_UPDATE_CHECKPOINT_BLOCK=BlockNumber(25934000),
            CONFIG_UPDATE_LAST_EVENT_IPFS_HASH='QmeCywDfupWC7jz5EDHsU5yEb2unAhn8iSGWBUEdrMjdMc',
            EXIT_SIGNATURES_CHECKPOINT_BLOCK=BlockNumber(25934000),
            VAULT_VALIDATORS_IPFS_HASH=(
                'bafybeigywptyz3lo7pb4rby2gwagdamyeahw2yklijupwfxqjjzfuqebpm'
            ),
            VAULT_VALIDATORS_LAST_BLOCK=BlockNumber(25934000),
        ),
    ),
    HOODI: NetworkConfig(
        **_base_config(
            HOODI,
            GENESIS_VALIDATORS_IPFS_HASH=(
                'bafybeiewzbkv7m53muugperb3w4j7uxvw6d5mmry7l73igcxutmaqmq3q4'
            ),
            GENESIS_VALIDATORS_LAST_BLOCK=BlockNumber(3583807),
        ),
        WALLET_BALANCE_SYMBOL='HoodiETH',
        VAULT_BALANCE_SYMBOL='HoodiETH',
        DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x93a3f880E07B27dacA6Ef2d3C23E77DBd6294487'
        ),
        HOT_WALLET_MIN_BALANCE=Web3.to_wei('0.03', 'ether'),
        STAKEWISE_API_URL='https://hoodi-api.stakewise.io/graphql',
        RATED_API_URL='https://api.rated.network',
        DEFAULT_DVT_RELAYER_ENDPOINT='https://hoodi-dvt-relayer.stakewise.io',
        MAX_FEE_PER_GAS_GWEI=Gwei(10),
        CHECKPOINTS=CheckpointsConfig(
            CONFIG_UPDATE_CHECKPOINT_BLOCK=BlockNumber(3584000),
            CONFIG_UPDATE_LAST_EVENT_IPFS_HASH='QmVqQyJ1TckGVshvYP7iMXhG46w5i2JyciwDqPkEnXijDH',
            EXIT_SIGNATURES_CHECKPOINT_BLOCK=BlockNumber(3584000),
            VAULT_VALIDATORS_IPFS_HASH=(
                'bafkreihalltsgohglgsphglrbmbcnvbuohgwfqa5r5wnnsgiic53zpkliy'
            ),
            VAULT_VALIDATORS_LAST_BLOCK=BlockNumber(3584000),
        ),
    ),
    GNOSIS: NetworkConfig(
        **_base_config(
            GNOSIS,
            GENESIS_VALIDATORS_IPFS_HASH=(
                'bafybeid432mdt244stggmmloubn2aoe2563abtyskdmipmd6p4lzh54jl4'
            ),
            GENESIS_VALIDATORS_LAST_BLOCK=BlockNumber(48127042),
        ),
        WALLET_BALANCE_SYMBOL='xDAI',
        VAULT_BALANCE_SYMBOL='GNO',
        DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x58e16621B5c0786D6667D2d54E28A20940269E16'
        ),
        HOT_WALLET_MIN_BALANCE=Web3.to_wei('0.01', 'ether'),
        STAKEWISE_API_URL='https://gnosis-api.stakewise.io/graphql',
        RATED_API_URL='https://api.rated.network',
        DEFAULT_DVT_RELAYER_ENDPOINT='gnosis-dvt-relayer.stakewise.io',
        MAX_FEE_PER_GAS_GWEI=Gwei(2),
        CHECKPOINTS=CheckpointsConfig(
            CONFIG_UPDATE_CHECKPOINT_BLOCK=BlockNumber(48148000),
            CONFIG_UPDATE_LAST_EVENT_IPFS_HASH='QmWCdkpTifsge6t2NTwyb89PCXDXFNkfee9T5ZctEfrDDw',
            EXIT_SIGNATURES_CHECKPOINT_BLOCK=BlockNumber(48148000),
            VAULT_VALIDATORS_IPFS_HASH=(
                'bafybeicl67j5kcvn5lzhydi5pmp5wjnot23topveijwggodb2ueay2qk5a'
            ),
            VAULT_VALIDATORS_LAST_BLOCK=BlockNumber(48148000),
        ),
    ),
    CHIADO: NetworkConfig(
        **_base_config(CHIADO),
        WALLET_BALANCE_SYMBOL='xDAI',
        VAULT_BALANCE_SYMBOL='GNO',
        DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xFAce8504462AEb9BB6ae7Ecb206BD7B1EdF7956D'
        ),
        HOT_WALLET_MIN_BALANCE=Web3.to_wei('0.01', 'ether'),
        STAKEWISE_API_URL='https://chiado-api.stakewise.io/graphql',
        RATED_API_URL='https://api.rated.network',
        DEFAULT_DVT_RELAYER_ENDPOINT='chiado-dvt-relayer.stakewise.io',
        MAX_FEE_PER_GAS_GWEI=Gwei(2),
        # No checkpoints for Chiado: scan from the keeper genesis block as before.
        CHECKPOINTS=CheckpointsConfig(
            CONFIG_UPDATE_CHECKPOINT_BLOCK=BlockNumber(
                BASE_NETWORKS[CHIADO].KEEPER_GENESIS_BLOCK - 1
            ),
            CONFIG_UPDATE_LAST_EVENT_IPFS_HASH='',
            EXIT_SIGNATURES_CHECKPOINT_BLOCK=BlockNumber(
                BASE_NETWORKS[CHIADO].KEEPER_GENESIS_BLOCK - 1
            ),
            VAULT_VALIDATORS_IPFS_HASH='',
            VAULT_VALIDATORS_LAST_BLOCK=BlockNumber(0),
        ),
    ),
}
