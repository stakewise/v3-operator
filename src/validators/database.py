import logging

from eth_typing import BlockNumber, ChecksumAddress, HexStr

from src.common.clients import db_client
from src.config.settings import settings
from src.validators.typings import NetworkValidator, VaultValidator

logger = logging.getLogger(__name__)


class NetworkValidatorCrud:
    @property
    def NETWORK_VALIDATORS_TABLE(self) -> str:
        return f'{settings.network}_network_validators'

    def save_network_validators(self, validators: list[NetworkValidator]) -> None:
        """Saves network validators."""
        with db_client.get_db_connection() as conn:
            conn.executemany(
                f'INSERT INTO {self.NETWORK_VALIDATORS_TABLE} '
                ' VALUES(:public_key, :block_number) ON CONFLICT DO NOTHING',
                [(val.public_key, val.block_number) for val in validators],
            )

    def get_last_network_validator(self) -> NetworkValidator | None:
        """Fetches last network validator."""
        network_validators_table = self.NETWORK_VALIDATORS_TABLE
        with db_client.get_db_connection() as conn:
            res = conn.execute(
                f'''SELECT public_key, block_number
                    FROM {network_validators_table} ORDER BY block_number DESC LIMIT 1'''
            ).fetchone()
            if res:
                return NetworkValidator(public_key=res[0], block_number=res[1])
            return None

    def is_validator_registered(self, public_key: HexStr) -> bool:
        """Checks whether validator is registered."""
        network_validators_table = self.NETWORK_VALIDATORS_TABLE
        with db_client.get_db_connection() as conn:
            res = conn.execute(
                f'SELECT public_key FROM {network_validators_table} WHERE (public_key = ?)',
                (public_key,),
            )
            return res.fetchone() is not None

    def get_next_validator_index(self, latest_public_keys: list[HexStr]) -> int:
        """Retrieves the index for the next validator."""
        with db_client.get_db_connection() as conn:
            if latest_public_keys:
                cur = conn.execute(
                    f'''SELECT COUNT(*) FROM {self.NETWORK_VALIDATORS_TABLE}
                        WHERE public_key NOT IN ({','.join(['?'] * len(latest_public_keys))})''',
                    latest_public_keys,
                )
            else:
                cur = conn.execute(f'SELECT COUNT(*) FROM {self.NETWORK_VALIDATORS_TABLE}')

            index = cur.fetchone()[0]

        return index + len(latest_public_keys)

    def setup(self) -> None:
        """Creates tables."""
        with db_client.get_db_connection() as conn:
            conn.execute(
                f"""
                        CREATE TABLE IF NOT EXISTS {self.NETWORK_VALIDATORS_TABLE} (
                            public_key VARCHAR(98) UNIQUE NOT NULL,
                            block_number INTEGER NOT NULL
                        )
                        """
            )


class VaultCrud:
    @property
    def VAULTS_TABLE(self) -> str:
        return f'{settings.network}_vaults'

    def save_vaults(self, vaults: list[ChecksumAddress]) -> None:
        with db_client.get_db_connection() as conn:
            conn.executemany(
                f'INSERT INTO {self.VAULTS_TABLE} '
                ' VALUES(:vault_address,:block_number) ON CONFLICT DO NOTHING',
                [(vault_address, 0) for vault_address in vaults],
            )

    def get_vault_checkpoint(self, vault_address: ChecksumAddress) -> BlockNumber | None:
        with db_client.get_db_connection() as conn:
            results = conn.execute(
                f'''SELECT checkpoint_block_number
                    FROM {self.VAULTS_TABLE}
                    WHERE (vault_address = ?)
                    ''',
                (vault_address,),
            ).fetchone()
            return BlockNumber(results[0]) if results else None

    def update_vault_checkpoint(
        self, vault_address: ChecksumAddress, block_number: BlockNumber
    ) -> None:
        with db_client.get_db_connection() as conn:
            conn.execute(
                f'''INSERT INTO {self.VAULTS_TABLE}
                   VALUES (:vault_address, :block_number)
                   ON CONFLICT (vault_address) DO UPDATE
                   SET checkpoint_block_number = :block_number
                    ''',
                (vault_address, block_number),
            )

    def setup(self) -> None:
        """Creates tables."""
        with db_client.get_db_connection() as conn:
            conn.execute(
                f"""
                        CREATE TABLE IF NOT EXISTS {self.VAULTS_TABLE} (
                            vault_address VARCHAR(42) UNIQUE NOT NULL,
                            checkpoint_block_number INTEGER NOT NULL
                        )
                        """
            )


class VaultValidatorCrud:
    @property
    def VAULT_VALIDATORS_TABLE(self) -> str:
        return f'{settings.network}_vault_validators'

    def save_vault_validators(self, validators: list[VaultValidator]) -> None:
        with db_client.get_db_connection() as conn:
            conn.executemany(
                f'INSERT INTO {self.VAULT_VALIDATORS_TABLE} '
                ' VALUES(:vault_address,:public_key, :block_number) ON CONFLICT DO NOTHING',
                [(val.vault_address, val.public_key, val.block_number) for val in validators],
            )

    def get_vault_validators(self, vault_address: ChecksumAddress) -> list[VaultValidator]:
        vault_validators_table = self.VAULT_VALIDATORS_TABLE
        with db_client.get_db_connection() as conn:
            results = conn.execute(
                f'''SELECT vault_address, public_key, block_number
                    FROM {vault_validators_table}
                    WHERE (vault_address = ?)
                    ORDER BY block_number''',
                (vault_address,),
            ).fetchall()
            return [
                VaultValidator(vault_address=res[0], public_key=res[1], block_number=res[2])
                for res in results
            ]

    def setup(self) -> None:
        """Creates tables."""
        with db_client.get_db_connection() as conn:
            conn.execute(
                f"""
                        CREATE TABLE IF NOT EXISTS {self.VAULT_VALIDATORS_TABLE} (
                            vault_address VARCHAR(42) NOT NULL,
                            public_key VARCHAR(98) UNIQUE NOT NULL,
                            block_number INTEGER NOT NULL
                        )
                        """
            )
