import json
import os
from typing import Dict

from web3.contract import AsyncContract

from src.common.clients import execution_client
from src.config.networks import ETH_NETWORKS
from src.config.settings import NETWORK, NETWORK_CONFIG, VAULT_CONTRACT_ADDRESS


def _load_abi(abi_path: str) -> Dict:
    current_dir = os.path.dirname(__file__)
    with open(os.path.join(current_dir, abi_path)) as f:
        return json.load(f)


def get_vault_contract() -> AsyncContract:
    """:returns instance of `Vault` contract."""
    if NETWORK in ETH_NETWORKS:
        abi_path = 'abi/IEthVault.json'
        return execution_client.eth.contract(
            address=VAULT_CONTRACT_ADDRESS, abi=_load_abi(abi_path)
        )  # type: ignore

    raise NotImplementedError('networks other than Ethereum not supported')


def get_validators_registry_contract() -> AsyncContract:
    """:returns instance of `ValidatorsRegistry` contract."""
    abi_path = 'abi/IValidatorsRegistry.json'
    return execution_client.eth.contract(
        address=NETWORK_CONFIG.VALIDATORS_REGISTRY_CONTRACT_ADDRESS, abi=_load_abi(abi_path)
    )  # type: ignore


def get_oracles_contract() -> AsyncContract:
    """:returns instance of `Oracles` contract."""
    abi_path = 'abi/IOracles.json'
    return execution_client.eth.contract(
        address=NETWORK_CONFIG.ORACLES_CONTRACT_ADDRESS, abi=_load_abi(abi_path)
    )  # type: ignore


def get_keeper_contract() -> AsyncContract:
    """:returns instance of `Keeper` contract."""
    abi_path = 'abi/IKeeper.json'
    return execution_client.eth.contract(
        address=NETWORK_CONFIG.KEEPER_CONTRACT_ADDRESS, abi=_load_abi(abi_path)
    )  # type: ignore


vault_contract = get_vault_contract()
validators_registry_contract = get_validators_registry_contract()
oracles_contract = get_oracles_contract()
keeper_contract = get_keeper_contract()
