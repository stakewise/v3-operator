from src.eth.contracts import (get_deposit_contract, get_oracle_contract,
                               get_vault_contract)


def get_vault_balance(block_number: int):
    vault_contract = get_vault_contract()
    return vault_contract.functions.totalSupply().call(
        block_identifier=block_number
    )


def get_vault_validators_root(block_number: int):
    vault_contract = get_vault_contract()
    return vault_contract.functions.validatorRoot().call(
        block_identifier=block_number
    )


def get_registered_validators(from_block, to_block) -> int:
    deposit_contract = get_deposit_contract()
    validators = deposit_contract.events.DepositEvent.getLogs(
        fromBlock=from_block, toBlock=to_block
    )

    return validators


def get_oracles_endpoints(block_number: int) -> list[str]:
    oracle_contract = get_oracle_contract()
    oracle_endoints = oracle_contract.functions.oracleEndpoints.call(
        block_identifier=block_number
    )
    return oracle_endoints
