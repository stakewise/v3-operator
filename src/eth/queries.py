from web3.types import BlockNumber

from .contracts import get_oracle_contract, get_vault_contract
from .execution import ExecutionClient


def get_block_number() -> BlockNumber:
    web3_client = ExecutionClient().get_client()
    return web3_client.eth.block_number


def get_vault_balance(block_number: int):
    vault_contract = get_vault_contract()
    return vault_contract.functions.totalSupply().call(block_identifier=block_number)


def get_vault_validators_root(block_number: int):
    vault_contract = get_vault_contract()
    return vault_contract.functions.validatorRoot().call(block_identifier=block_number)


def get_oracles_endpoints(block_number: int) -> list[str]:
    oracle_contract = get_oracle_contract()
    oracle_endoints = oracle_contract.functions.oracleEndpoints.call(block_identifier=block_number)
    return oracle_endoints
