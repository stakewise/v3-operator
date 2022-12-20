import json
import os
from typing import Dict

from web3.contract import AsyncContract

from src.common.clients import execution_client
from src.config.settings import NETWORK_CONFIG, VAULT_CONTRACT_ADDRESS


def _load_abi(abi_path: str) -> Dict:
    current_dir = os.path.dirname(__file__)
    with open(os.path.join(current_dir, abi_path)) as f:
        return json.load(f)


def get_vault_contract() -> AsyncContract:
    """:returns instance of `BaseVault` contract."""
    abi_path = 'abi/IBaseVault.json'
    return execution_client.eth.contract(
        address=VAULT_CONTRACT_ADDRESS, abi=_load_abi(abi_path)
    )  # type: ignore


def get_validators_registry_contract() -> AsyncContract:
    """:returns instance of `ValidatorsRegistry` contract."""
    abi_path = 'abi/IValidatorsRegistry.json'
    return execution_client.eth.contract(
        address=NETWORK_CONFIG.VALIDATORS_REGISTRY_CONTRACT_ADDRESS, abi=_load_abi(abi_path)
    )  # type: ignore


vault_contract = get_vault_contract()
validators_registry_contract = get_validators_registry_contract()
