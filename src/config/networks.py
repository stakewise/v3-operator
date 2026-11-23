from dataclasses import asdict, dataclass, fields

from eth_typing import BlockNumber, ChecksumAddress
from sw_utils.networks import GNOSIS, HOODI, MAINNET
from sw_utils.networks import NETWORKS as BASE_NETWORKS
from sw_utils.networks import BaseNetworkConfig, CheckpointsConfig
from web3 import Web3
from web3.types import Gwei, Wei

AVAILABLE_NETWORKS = [MAINNET, HOODI, GNOSIS]
RATED_NETWORKS = [MAINNET]


@dataclass
class OperatorCheckpointsConfig(CheckpointsConfig):
    """
    Operator-specific checkpoints on top of the shared sw-utils ones.
    """

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
    CHECKPOINTS: OperatorCheckpointsConfig


def _load_base_kwargs(network: str) -> dict:
    """
    Returns sw-utils network config fields as kwargs.
    `CHECKPOINTS` is skipped: the operator extends it with its own fields.
    """
    # Shallow copy: `dataclasses.asdict` would also convert nested dataclasses
    # into plain dicts, breaking attribute access on them.
    base = BASE_NETWORKS[network]
    ignored_fields = ('CHECKPOINTS',)
    return {f.name: getattr(base, f.name) for f in fields(base) if f.name not in ignored_fields}


NETWORKS: dict[str, NetworkConfig] = {
    MAINNET: NetworkConfig(
        **_load_base_kwargs(MAINNET),
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
        CHECKPOINTS=OperatorCheckpointsConfig(
            **asdict(BASE_NETWORKS[MAINNET].CHECKPOINTS),
            EXIT_SIGNATURES_CHECKPOINT_BLOCK=BlockNumber(25934000),
            VAULT_VALIDATORS_IPFS_HASH=(
                'bafybeigywptyz3lo7pb4rby2gwagdamyeahw2yklijupwfxqjjzfuqebpm'
            ),
            VAULT_VALIDATORS_LAST_BLOCK=BlockNumber(25934000),
        ),
    ),
    HOODI: NetworkConfig(
        **_load_base_kwargs(HOODI),
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
        CHECKPOINTS=OperatorCheckpointsConfig(
            **asdict(BASE_NETWORKS[HOODI].CHECKPOINTS),
            EXIT_SIGNATURES_CHECKPOINT_BLOCK=BlockNumber(3584000),
            VAULT_VALIDATORS_IPFS_HASH=(
                'bafkreihalltsgohglgsphglrbmbcnvbuohgwfqa5r5wnnsgiic53zpkliy'
            ),
            VAULT_VALIDATORS_LAST_BLOCK=BlockNumber(3584000),
        ),
    ),
    GNOSIS: NetworkConfig(
        **_load_base_kwargs(GNOSIS),
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
        CHECKPOINTS=OperatorCheckpointsConfig(
            **asdict(BASE_NETWORKS[GNOSIS].CHECKPOINTS),
            EXIT_SIGNATURES_CHECKPOINT_BLOCK=BlockNumber(48148000),
            VAULT_VALIDATORS_IPFS_HASH=(
                'bafybeicl67j5kcvn5lzhydi5pmp5wjnot23topveijwggodb2ueay2qk5a'
            ),
            VAULT_VALIDATORS_LAST_BLOCK=BlockNumber(48148000),
        ),
    ),
}
