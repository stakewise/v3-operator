import json
import os

from web3.contract import AsyncContract
from web3.types import ChecksumAddress

from src.common.clients import execution_client
from src.config.settings import settings


class ContractWrapper:
    abi_path: str = ''
    settings_key: str = ''

    @property
    def contract_address(self) -> ChecksumAddress:
        return getattr(settings.NETWORK_CONFIG, self.settings_key)

    @property
    def contract(self) -> AsyncContract:
        current_dir = os.path.dirname(__file__)
        with open(os.path.join(current_dir, self.abi_path), encoding='utf-8') as f:
            abi = json.load(f)
        return execution_client.eth.contract(
            abi=abi, address=self.contract_address
        )  # type: ignore


class VaultContract(ContractWrapper):
    abi_path = 'abi/IEthVault.json'

    def __init__(self):
        self.address = settings.VAULT_CONTRACT_ADDRESS

    @property
    def contract_address(self) -> ChecksumAddress:
        return self.address


class ValidatorsRegistryContract(ContractWrapper):
    abi_path = 'abi/IValidatorsRegistry.json'
    settings_key = 'VALIDATORS_REGISTRY_CONTRACT_ADDRESS'


class OraclesContract(ContractWrapper):
    abi_path = 'abi/IOracles.json'
    settings_key = 'ORACLES_CONTRACT_ADDRESS'


class KeeperContract(ContractWrapper):
    abi_path = 'abi/IKeeper.json'
    settings_key = 'KEEPER_CONTRACT_ADDRESS'
