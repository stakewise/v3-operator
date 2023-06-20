import json
import os
from functools import cached_property

from sw_utils.decorators import backoff_aiohttp_errors
from web3.contract import AsyncContract
from web3.types import ChecksumAddress

from src.common.clients import execution_client, read_only_execution_client
from src.config.settings import DEFAULT_RETRY_TIME, settings


class ContractWrapper:
    relative_abi_path: str = ''
    settings_key: str = ''

    @property
    def contract_address(self) -> ChecksumAddress:
        return getattr(settings.NETWORK_CONFIG, self.settings_key)

    @property
    def abi_path(self) -> str:
        current_dir = os.path.dirname(__file__)
        return os.path.join(current_dir, self.relative_abi_path)

    @cached_property
    def contract(self) -> AsyncContract:
        with open(self.abi_path, encoding='utf-8') as f:
            abi = json.load(f)
        client = execution_client
        return client.eth.contract(abi=abi, address=self.contract_address)  # type: ignore

    @cached_property
    def read_only_contract(self) -> AsyncContract:
        with open(self.abi_path, encoding='utf-8') as f:
            abi = json.load(f)
        client = read_only_execution_client
        return client.eth.contract(abi=abi, address=self.contract_address)  # type: ignore

    def __getattr__(self, item):
        return getattr(self.contract, item)


class VaultContract(ContractWrapper):
    relative_abi_path = 'abi/IEthVault.json'

    @property
    def contract_address(self) -> ChecksumAddress:
        return settings.VAULT_CONTRACT_ADDRESS

    @backoff_aiohttp_errors(max_time=DEFAULT_RETRY_TIME)
    async def get_validators_root(self):
        return await self.read_only_contract.functions.validatorsRoot().call()


class ValidatorsRegistryContract(ContractWrapper):
    relative_abi_path = 'abi/IValidatorsRegistry.json'
    settings_key = 'VALIDATORS_REGISTRY_CONTRACT_ADDRESS'


class OraclesContract(ContractWrapper):
    relative_abi_path = 'abi/IOracles.json'
    settings_key = 'ORACLES_CONTRACT_ADDRESS'


class KeeperContract(ContractWrapper):
    relative_abi_path = 'abi/IKeeper.json'
    settings_key = 'KEEPER_CONTRACT_ADDRESS'


vault_contract = VaultContract()
validators_registry_contract = ValidatorsRegistryContract()
oracles_contract = OraclesContract()
keeper_contract = KeeperContract()
