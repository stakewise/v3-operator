import logging

from eth_typing import HexStr
from psycopg.rows import class_row
from psycopg.sql import SQL, Identifier
from web3 import Web3

from src.common.clients import db_client, ipfs_fetch_client
from src.config.networks import GOERLI
from src.config.settings import (
    GOERLI_GENESIS_VALIDATORS_IPFS_HASH,
    NETWORK,
    NETWORK_CONFIG,
)
from src.validators.typings import DepositData, NetworkValidator, ValidatorsRoot

NETWORK_VALIDATORS_TABLE = f'{NETWORK}_network_validators'
DEPOSIT_DATA_TABLE = f'{NETWORK}_deposit_data'
VALIDATORS_ROOT_TABLE = f'{NETWORK}_validators_root'

logger = logging.getLogger(__name__)


async def load_genesis_validators() -> None:
    """
    In some test networks (e.g. Goerli) genesis validators
    are not registered through the registry contract.
    """
    if NETWORK != GOERLI or get_last_network_validator() is not None:
        return

    pub_keys = await ipfs_fetch_client.fetch_bytes(GOERLI_GENESIS_VALIDATORS_IPFS_HASH)
    genesis_validators: list[NetworkValidator] = []
    for i in range(0, len(pub_keys), 48):
        genesis_validators.append(
            NetworkValidator(
                public_key=Web3.to_hex(pub_keys[i: i + 48]),
                block_number=NETWORK_CONFIG.VALIDATORS_REGISTRY_GENESIS_BLOCK,
            )
        )

    save_network_validators(genesis_validators)
    logger.info('Loaded %d Goerli genesis validators', len(genesis_validators))


def save_validators_root(root: ValidatorsRoot) -> None:
    """Cleans up previous validators root and saves the new one."""
    with db_client.get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(SQL('DELETE FROM {}').format(Identifier(VALIDATORS_ROOT_TABLE)))
            cur.execute(
                SQL(
                    'INSERT INTO {} (root, ipfs_hash, block_number) VALUES (%s, %s, %s)'
                ).format(Identifier(VALIDATORS_ROOT_TABLE)),
                (root.root, root.ipfs_hash, root.block_number),
            )


def get_last_validators_root() -> ValidatorsRoot | None:
    """Fetches the last vault validators root."""
    with db_client.get_db_connection() as conn:
        with conn.cursor(row_factory=class_row(ValidatorsRoot)) as cur:
            cur.execute(
                SQL('SELECT * FROM {} ORDER BY block_number DESC LIMIT 1').format(
                    Identifier(VALIDATORS_ROOT_TABLE)
                ),
            )
            return cur.fetchone()


def save_deposit_data(deposit_data: list[DepositData]) -> None:
    """Cleans up previous deposit data and saves the new one."""
    with db_client.get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(SQL('DELETE FROM {}').format(Identifier(DEPOSIT_DATA_TABLE)))
            if not deposit_data:
                return

            cur.executemany(
                SQL(
                    'INSERT INTO {} (validator_index, public_key, signature) VALUES (%s, %s, %s)'
                ).format(
                    Identifier(DEPOSIT_DATA_TABLE),
                ),
                [
                    (
                        data.validator_index,
                        data.public_key,
                        data.signature
                    )
                    for data in deposit_data
                ],
            )


def get_deposit_data() -> list[DepositData]:
    """Fetches all the deposit data."""
    with db_client.get_db_connection() as conn:
        with conn.cursor(row_factory=class_row(DepositData)) as cur:
            cur.execute(
                SQL('SELECT * FROM {} ORDER BY validator_index ASC').format(
                    Identifier(DEPOSIT_DATA_TABLE),
                ),
            )
            return cur.fetchall()


def save_network_validators(validators: list[NetworkValidator]) -> None:
    """Saves network validators."""
    with db_client.get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.executemany(
                SQL(
                    'INSERT INTO {} (public_key, block_number)'
                    ' VALUES (%s, %s) ON CONFLICT DO NOTHING'
                ).format(Identifier(NETWORK_VALIDATORS_TABLE)),
                [(val.public_key, val.block_number) for val in validators],
            )


def get_last_network_validator() -> NetworkValidator | None:
    """Fetches last network validator."""
    with db_client.get_db_connection() as conn:
        with conn.cursor(row_factory=class_row(NetworkValidator)) as cur:
            cur.execute(
                SQL('SELECT * FROM {} ORDER BY block_number DESC LIMIT 1').format(
                    Identifier(NETWORK_VALIDATORS_TABLE),
                )
            )
            return cur.fetchone()


def is_validator_registered(public_key: HexStr) -> bool:
    """Checks whether validator is registered."""
    with db_client.get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                SQL('SELECT public_key FROM {} WHERE (public_key = %s)').format(
                    Identifier(NETWORK_VALIDATORS_TABLE),
                ),
                (public_key,),
            )
            return cur.fetchone() is not None


def get_next_validator_index(latest_public_keys: list[HexStr]) -> int:
    """Retrieves the index for the next validator."""
    with db_client.get_db_connection() as conn:
        with conn.cursor() as cur:
            if latest_public_keys:
                cur.execute(
                    SQL('SELECT COUNT(*) FROM {} WHERE NOT (public_key = ANY(%s))').format(
                        Identifier(NETWORK_VALIDATORS_TABLE),
                    ),
                    (latest_public_keys,),
                )
            else:
                cur.execute(
                    SQL('SELECT COUNT(*) FROM {}').format(
                        Identifier(NETWORK_VALIDATORS_TABLE),
                    )
                )
            index = cur.fetchone()[0]

    return index + len(latest_public_keys)


async def setup() -> None:
    """Creates tables."""
    with db_client.get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                SQL(
                    """
                    CREATE TABLE IF NOT EXISTS {} (
                        public_key VARCHAR(98) UNIQUE NOT NULL,
                        block_number INTEGER NOT NULL
                    )
                    """
                ).format(Identifier(NETWORK_VALIDATORS_TABLE)),
            )
            cur.execute(
                SQL(
                    """
                    CREATE TABLE IF NOT EXISTS {} (
                        validator_index INTEGER UNIQUE NOT NULL,
                        public_key VARCHAR(98) UNIQUE NOT NULL,
                        signature VARCHAR(194) UNIQUE NOT NULL
                    )
                    """
                ).format(Identifier(DEPOSIT_DATA_TABLE)),
            )
            cur.execute(
                SQL(
                    """
                    CREATE TABLE IF NOT EXISTS {} (
                        root VARCHAR(66) NOT NULL,
                        ipfs_hash VARCHAR(66) NOT NULL,
                        block_number INTEGER NOT NULL
                    )
                    """
                ).format(Identifier(VALIDATORS_ROOT_TABLE)),
            )

    await load_genesis_validators()
