import json
import os

from web3.contract import Contract

from src.config.settings import NETWORK_CONFIG

from .execution import ExecutionClient, LightExecutionClient


def get_vault_contract() -> Contract:
    """:returns instance of Stakewise Vault contract."""
    abi_path = 'abi/vault.json'

    current_dir = os.path.dirname(__file__)
    with open(os.path.join(current_dir, abi_path)) as f:
        abi = json.load(f)

    web3_client = ExecutionClient().get_client()
    return web3_client.eth.contract(
        address=NETWORK_CONFIG.VAULT_CONTRACT_ADDRESS,
        abi=abi,
    )


def get_oracle_contract() -> Contract:
    """:returns instance of Stakewise Oracle contract."""
    abi_path = 'abi/oracle.json'

    current_dir = os.path.dirname(__file__)
    with open(os.path.join(current_dir, abi_path)) as f:
        abi = json.load(f)

    web3_client = ExecutionClient().get_client()
    return web3_client.eth.contract(
        address=NETWORK_CONFIG.ORACLE_CONTRACT_ADDRESS,
        abi=abi,
    )


def get_deposit_contract() -> Contract:
    """:returns instance of `ETH2 deposit` contract."""
    abi_path = 'abis/deposit.json'

    current_dir = os.path.dirname(__file__)
    with open(os.path.join(current_dir, abi_path)) as f:
        abi = json.load(f)
    web3_client = LightExecutionClient().get_client()
    return web3_client.eth.contract(
        address=NETWORK_CONFIG.DEPOSIT_CONTRACT_ADDRESS,
        abi=abi,
    )
