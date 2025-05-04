import base64
from collections import defaultdict
from pathlib import Path
from secrets import randbits
from typing import Generator
from unittest import mock

import milagro_bls_binding as bls
import pytest
from click.testing import CliRunner
from eth_typing import ChecksumAddress, HexAddress
from py_ecc.bls import G2ProofOfPossession
from web3 import Web3

from src.remote_db.commands import remote_db_group
from src.remote_db.database import KeyPairsCrud
from src.remote_db.tasks import _encrypt_private_key
from src.remote_db.typings import RemoteDatabaseKeyPair
from src.validators.typings import BLSPrivkey


@pytest.fixture
def _patch_check_db_connection() -> Generator:
    with mock.patch('src.remote_db.commands.check_db_connection', return_value=None):
        yield


@pytest.fixture
def _patch_get_db_connection() -> Generator:
    with (
        mock.patch('src.remote_db.tasks.get_db_connection'),
        mock.patch('src.remote_db.database.get_db_connection'),
    ):
        yield


@pytest.mark.usefixtures('_init_config', '_patch_check_db_connection', '_patch_get_db_connection')
class TestRemoteDbSetup:
    def test_setup_works(
        self,
        data_dir: Path,
        vault_address: HexAddress,
        runner: CliRunner,
    ):
        db_url = 'postgresql://user:password@localhost:5432/dbname'

        args = ['--db-url', db_url, '--vault', vault_address, '--data-dir', str(data_dir), 'setup']
        with (
            mock.patch.object(
                KeyPairsCrud, 'get_keypairs_count', return_value=0
            ) as get_keypairs_count_mock,
            mock.patch.object(
                ConfigsCrud, 'get_configs_count', return_value=0
            ) as get_configs_count_mock,
            mock.patch('src.remote_db.tasks.get_random_bytes', return_value=b'1'),
        ):
            result = runner.invoke(remote_db_group, args)
            assert get_keypairs_count_mock.call_count == 1
            assert get_configs_count_mock.call_count == 1

            output = (
                'Successfully configured remote database.\n'
                'Encryption key: MQ==\n'
                'NB! You must store your encryption in a secure cold storage!'
            )
            assert output.strip() == result.output.strip()

    def test_cleanup_works(
        self,
        data_dir: Path,
        vault_address: HexAddress,
        runner: CliRunner,
    ):
        db_url = 'postgresql://user:password@localhost:5432/dbname'
        args = [
            '--db-url',
            db_url,
            '--vault',
            vault_address,
            '--data-dir',
            str(data_dir),
            'cleanup',
        ]
        with (
            mock.patch.object(KeyPairsCrud, 'remove_keypairs') as remove_keypairs_mock,
            mock.patch.object(ConfigsCrud, 'remove_configs') as remove_configs_mock,
        ):
            result = runner.invoke(remote_db_group, args)
            assert remove_keypairs_mock.call_count == 1
            assert remove_configs_mock.call_count == 1

            output = 'Successfully removed all the entries for the ' f'{vault_address} vault.'
            assert output.strip() == result.output.strip()

    def test_setup_fails_when_keypairs_not_empty(
        self,
        data_dir: Path,
        vault_address: HexAddress,
        runner: CliRunner,
    ):
        db_url = 'postgresql://user:password@localhost:5432/dbname'

        args = ['--db-url', db_url, '--vault', vault_address, '--data-dir', str(data_dir), 'setup']
        with mock.patch.object(
            KeyPairsCrud, 'get_keypairs_count', return_value=1
        ) as get_keypairs_count_mock:
            result = runner.invoke(remote_db_group, args)
            assert get_keypairs_count_mock.call_count == 1

            output = (
                'Error: Error: the remote database is not empty. Please clean up with "clean" '
                'command first.'
            )
            assert output.strip() == result.output.strip()

    def test_setup_fails_when_configs_not_empty(
        self,
        data_dir: Path,
        vault_address: HexAddress,
        runner: CliRunner,
    ):
        db_url = 'postgresql://user:password@localhost:5432/dbname'

        args = ['--db-url', db_url, '--vault', vault_address, '--data-dir', str(data_dir), 'setup']
        with (
            mock.patch.object(KeyPairsCrud, 'get_keypairs_count', return_value=0),
            mock.patch.object(
                ConfigsCrud, 'get_configs_count', return_value=1
            ) as get_configs_count_mock,
        ):
            result = runner.invoke(remote_db_group, args)
            assert get_configs_count_mock.call_count == 1

            output = (
                'Error: Error: the remote database is not empty. Please clean up with "clean" '
                'command first.'
            )
            assert output.strip() == result.output.strip()


@pytest.mark.usefixtures(
    '_patch_check_db_connection',
    '_patch_get_db_connection',
)
@pytest.mark.usefixtures('_init_config', '_create_keys')
class TestRemoteDbUploadKeypairs:
    def test_upload_keypairs_works(
        self,
        data_dir: Path,
        vault_address: HexAddress,
        runner: CliRunner,
        execution_endpoints: str,
    ):
        db_url = 'postgresql://user:password@localhost:5432/dbname'
        encryption_key = '43ueY4nqsiajWHTnkdqrc3OWj2W+t0bbdBISJFjZ3Ck='

        args = [
            '--db-url',
            db_url,
            '--vault',
            vault_address,
            '--data-dir',
            str(data_dir),
            'upload-keypairs',
            '--execution-endpoints',
            execution_endpoints,
            '--encrypt-key',
            encryption_key,
        ]

        with mock.patch.object(KeyPairsCrud, 'get_first_keypair', return_value=None):
            result = runner.invoke(remote_db_group, args)
            output = f'Successfully uploaded keypairs for the {vault_address} vault.'
            assert output.strip() in result.output.strip()


@pytest.mark.usefixtures(
    '_patch_check_db_connection',
    '_patch_get_db_connection',
)
@pytest.mark.usefixtures('_init_config', '_create_keys')
class TestRemoteDbSetupWeb3Signer:
    def test_setup_web3signer_works(
        self,
        data_dir: Path,
        vault_address: HexAddress,
        runner: CliRunner,
        execution_endpoints: str,
    ):
        db_url = 'postgresql://user:password@localhost:5432/dbname'
        encryption_key = '43ueY4nqsiajWHTnkdqrc3OWj2W+t0bbdBISJFjZ3Ck='

        args = [
            '--db-url',
            db_url,
            '--vault',
            vault_address,
            '--data-dir',
            str(data_dir),
            'setup-web3signer',
            '--output-dir',
            './web3signer',
            '--encrypt-key',
            encryption_key,
        ]
        keypairs = _get_remote_db_keypairs(
            base64.b64decode(encryption_key), vault_address, total_validators=3
        )

        with (
            runner.isolated_filesystem(),
            mock.patch.object(KeyPairsCrud, 'get_first_keypair', return_value=keypairs[0]),
            mock.patch.object(KeyPairsCrud, 'get_keypairs', return_value=keypairs),
        ):
            result = runner.invoke(remote_db_group, args)
            output = 'Successfully retrieved web3signer private keys from the database.\n'
            assert output.strip() in result.output.strip()


@pytest.mark.usefixtures(
    '_patch_check_db_connection',
    '_patch_get_db_connection',
)
@pytest.mark.usefixtures('_init_config', '_create_keys')
class TestRemoteDbSetupValidator:
    def test_setup_validator(
        self,
        data_dir: Path,
        vault_address: HexAddress,
        runner: CliRunner,
    ):
        db_url = 'postgresql://user:password@localhost:5432/dbname'
        encryption_key = '43ueY4nqsiajWHTnkdqrc3OWj2W+t0bbdBISJFjZ3Ck='

        args = [
            '--db-url',
            db_url,
            '--vault',
            vault_address,
            '--data-dir',
            str(data_dir),
            'setup-validator',
            '--output-dir',
            './validator',
            '--validator-index',
            '0',
            '--total-validators',
            '1',
            '--web3signer-endpoint',
            'http://localhost:8080',
            '--fee-recipient',
            vault_address,
        ]
        keypairs = _get_remote_db_keypairs(
            base64.b64decode(encryption_key), vault_address, total_validators=3
        )

        with (
            runner.isolated_filesystem(),
            mock.patch.object(KeyPairsCrud, 'get_first_keypair', return_value=keypairs[0]),
            mock.patch.object(KeyPairsCrud, 'get_keypairs', return_value=keypairs),
        ):
            result = runner.invoke(remote_db_group, args)
            output = (
                'Generated configs with 3 keys '
                'for validator with index 0.\n'
                'Validator definitions for Lighthouse saved to '
                'validator/validator_definitions.yml file.\n'
                'Signer keys for Teku\\Prysm saved to '
                'validator/signer_keys.yml file.\n'
                'Proposer config for Teku\\Prysm saved to '
                'validator/proposer_config.json file.\n'
            )
            assert output.strip() in result.output.strip()


@pytest.mark.usefixtures(
    '_patch_check_db_connection',
    '_patch_get_db_connection',
)
@pytest.mark.usefixtures('_init_config', '_create_keys')
class TestRemoteDbSetupOperator:
    def test_setup_operator(
        self,
        data_dir: Path,
        vault_address: HexAddress,
        runner: CliRunner,
    ):
        db_url = 'postgresql://user:password@localhost:5432/dbname'
        encryption_key = '43ueY4nqsiajWHTnkdqrc3OWj2W+t0bbdBISJFjZ3Ck='

        args = [
            '--db-url',
            db_url,
            '--vault',
            vault_address,
            '--data-dir',
            str(data_dir),
            'setup-operator',
            '--output-dir',
            './operator',
        ]
        keypairs = _get_remote_db_keypairs(
            base64.b64decode(encryption_key), vault_address, total_validators=3
        )
        remote_config: dict[str, list[str]] = defaultdict(list)
        for keypair in keypairs:
            remote_config['public_key'].append(keypair.public_key)

        with (
            runner.isolated_filesystem(),
            mock.patch.object(KeyPairsCrud, 'get_first_keypair', return_value=keypairs[0]),
            mock.patch.object(KeyPairsCrud, 'get_keypairs', return_value=keypairs),
            mock.patch.object(ConfigsCrud, 'get_deposit_data', return_value=[]),
        ):
            result = runner.invoke(remote_db_group, args)
            output = 'Successfully created operator configuration file.\n'
            assert output.strip() in result.output.strip()


def _get_remote_db_keypairs(
    encryption_key: bytes, vault_address: HexAddress, total_validators: int
) -> list[RemoteDatabaseKeyPair]:
    keystores = {}
    for _ in range(total_validators):
        seed = randbits(256).to_bytes(32, 'big')
        private_key = BLSPrivkey(G2ProofOfPossession.KeyGen(seed).to_bytes(32, 'big'))
        public_key = Web3.to_hex(bls.SkToPk(private_key))
        keystores[public_key] = private_key

    key_records: list[RemoteDatabaseKeyPair] = []
    for public_key, private_key in keystores.items():  # pylint: disable=no-member
        encrypted_priv_key, nonce = _encrypt_private_key(private_key, encryption_key)
        key_records.append(
            RemoteDatabaseKeyPair(
                vault=ChecksumAddress(vault_address),
                public_key=public_key,
                private_key=Web3.to_hex(encrypted_priv_key),
                nonce=Web3.to_hex(nonce),
            )
        )
    return key_records
