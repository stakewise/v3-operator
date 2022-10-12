from decouple import config
from web3 import Web3

MAINNET = "mainnet"
GOERLI = "goerli"
HARBOUR_GOERLI = "harbour_goerli"
HARBOUR_MAINNET = "harbour_mainnet"
GNOSIS_CHAIN = "gnosis"

MAINNET_UPPER = MAINNET.upper()
GOERLI_UPPER = GOERLI.upper()
HARBOUR_GOERLI_UPPER = HARBOUR_GOERLI.upper()
HARBOUR_MAINNET_UPPER = HARBOUR_MAINNET.upper()
GNOSIS_CHAIN_UPPER = GNOSIS_CHAIN.upper()

NETWORKS = {
    MAINNET: dict(
        ETH1_ENDPOINT=config("ETH1_ENDPOINT", default=""),
        ETH2_ENDPOINT=config("ETH2_ENDPOINT", default=""),
        SLOTS_PER_EPOCH=32,
        SECONDS_PER_SLOT=12,
        PRIVATE_KEY=config("PRIVATE_KEY", default=""),

        VAULT_CONTRACT_ADDRESS=Web3.toChecksumAddress(
            "0x8a887282E67ff41d36C0b7537eAB035291461AcD"
        ),
        ORACLE_CONTRACT_ADDRESS=Web3.toChecksumAddress(
            "0x8a887282E67ff41d36C0b7537eAB035291461AcD"
        ),
        DEPOSIT_CONTRACT_ADDRESS=Web3.toChecksumAddress(
            "0x00000000219ab540356cBB839Cbe05303d7705Fa"
        ),
        ETH_ORACLES_ENDPOINT=config("ETH_ORACLES_ENDPOINT", default=""),
        OPERATOR_PRIVATE_KEY=config("OPERATOR_PRIVATE_KEY", default=""),
        IS_POA=False,
        VALIDATOR_DEPOSIT=Web3.toWei(32, "ether")
    ),
    HARBOUR_MAINNET: dict(
        ETH1_ENDPOINT=config("ETH1_ENDPOINT", default=""),
        ETH2_ENDPOINT=config("ETH2_ENDPOINT", default=""),
        SLOTS_PER_EPOCH=32,
        SECONDS_PER_SLOT=12,
        VAULT_CONTRACT_ADDRESS=Web3.toChecksumAddress(
            "0x8a887282E67ff41d36C0b7537eAB035291461AcD"
        ),
        ORACLE_CONTRACT_ADDRESS=Web3.toChecksumAddress(
            "0x8a887282E67ff41d36C0b7537eAB035291461AcD"
        ),
        DEPOSIT_CONTRACT_ADDRESS=Web3.toChecksumAddress(
            "0x00000000219ab540356cBB839Cbe05303d7705Fa"
        ),
        ETH_ORACLES_ENDPOINT=config("ETH_ORACLES_ENDPOINT", default=""),
        OPERATOR_PRIVATE_KEY=config("OPERATOR_PRIVATE_KEY", default=""),
        IS_POA=False,
        VALIDATOR_DEPOSIT=Web3.toWei(32, "ether")
    ),
    GOERLI: dict(
        ETH1_ENDPOINT=config("ETH1_ENDPOINT", default=""),
        ETH2_ENDPOINT=config("ETH2_ENDPOINT", default=""),
        SLOTS_PER_EPOCH=32,
        SECONDS_PER_SLOT=12,
        VAULT_CONTRACT_ADDRESS=Web3.toChecksumAddress(
            "0x8a887282E67ff41d36C0b7537eAB035291461AcD"
        ),
        ORACLE_CONTRACT_ADDRESS=Web3.toChecksumAddress(
            "0x8a887282E67ff41d36C0b7537eAB035291461AcD"
        ),
        DEPOSIT_CONTRACT_ADDRESS=Web3.toChecksumAddress(
            "0x00000000219ab540356cBB839Cbe05303d7705Fa"
        ),
        ETH_ORACLES_ENDPOINT=config("ETH_ORACLES_ENDPOINT", default=""),
        OPERATOR_PRIVATE_KEY=config("OPERATOR_PRIVATE_KEY", default=""),
        IS_POA=True,
        VALIDATOR_DEPOSIT=Web3.toWei(32, "ether")
    ),
    HARBOUR_GOERLI: dict(
        ETH1_ENDPOINT=config("ETH1_ENDPOINT", default=""),
        ETH2_ENDPOINT=config("ETH2_ENDPOINT", default=""),
        SLOTS_PER_EPOCH=32,
        SECONDS_PER_SLOT=12,
        VAULT_CONTRACT_ADDRESS=Web3.toChecksumAddress(
            "0x8a887282E67ff41d36C0b7537eAB035291461AcD"
        ),
        ORACLE_CONTRACT_ADDRESS=Web3.toChecksumAddress(
            "0x8a887282E67ff41d36C0b7537eAB035291461AcD"
        ),
        DEPOSIT_CONTRACT_ADDRESS=Web3.toChecksumAddress(
            "0x00000000219ab540356cBB839Cbe05303d7705Fa"
        ),
        ETH_ORACLES_ENDPOINT=config("ETH_ORACLES_ENDPOINT", default=""),
        OPERATOR_PRIVATE_KEY=config("OPERATOR_PRIVATE_KEY", default=""),
        IS_POA=True,
        VALIDATOR_DEPOSIT=Web3.toWei(32, "ether")
    ),
    GNOSIS_CHAIN: dict(
        ETH1_ENDPOINT=config("ETH1_ENDPOINT", default=""),
        ETH2_ENDPOINT=config("ETH2_ENDPOINT", default=""),
        SLOTS_PER_EPOCH=32,
        SECONDS_PER_SLOT=12,
        VAULT_CONTRACT_ADDRESS=Web3.toChecksumAddress(
            "0x8a887282E67ff41d36C0b7537eAB035291461AcD"
        ),
        ORACLE_CONTRACT_ADDRESS=Web3.toChecksumAddress(
            "0x8a887282E67ff41d36C0b7537eAB035291461AcD"
        ),
        DEPOSIT_CONTRACT_ADDRESS=Web3.toChecksumAddress(
            "0x00000000219ab540356cBB839Cbe05303d7705Fa"
        ),
        ETH_ORACLES_ENDPOINT=config("ETH_ORACLES_ENDPOINT", default=""),
        OPERATOR_PRIVATE_KEY=config("OPERATOR_PRIVATE_KEY", default=""),
        IS_POA=True,
        VALIDATOR_DEPOSIT=Web3.toWei(1, "ether")
    ),
}
