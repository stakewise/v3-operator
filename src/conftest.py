# pylint: disable=redefined-outer-name
# pylint: disable=unused-argument
import os
import re
from pathlib import Path
from random import randint
from tempfile import TemporaryDirectory
from typing import Callable, Generator
from unittest import mock

import ecies
import milagro_bls_binding as bls
import pytest
from _pytest.fixtures import SubRequest
from aioresponses import CallbackResult, aioresponses
from click.testing import CliRunner
from eth_typing import HexAddress, HexStr
from sw_utils.tests import faker
from web3 import Web3

from src.commands.create_keys import create_keys
from src.commands.create_wallet import create_wallet
from src.commands.generate_key_shares import generate_key_shares
from src.common.credentials import CredentialManager
from src.common.typings import Oracles
from src.common.vault_config import VaultConfig
from src.config.networks import GOERLI
from src.config.settings import settings
from src.validators.signing.remote import RemoteSignerConfiguration
from src.validators.signing.tests.oracle_functions import OracleCommittee
from src.validators.typings import BLSPrivkey, KeystoreFile
from src.validators.utils import _process_keystore_file


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    with TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def data_dir(temp_dir: Path) -> Path:
    data_dir = temp_dir / 'data'
    data_dir.mkdir()
    return data_dir


@pytest.fixture
def keystores_dir(vault_dir: Path, _init_vault) -> Path:
    keystores_dir = vault_dir / 'keystores'
    keystores_dir.mkdir(exist_ok=True)
    return keystores_dir


@pytest.fixture
def _test_keystore_password() -> str:
    return 'test_password'


@pytest.fixture
def _test_keystore_password_file(keystores_dir: Path, _test_keystore_password: str) -> Path:
    filepath = keystores_dir / 'password.txt'
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(_test_keystore_password)
    return filepath


@pytest.fixture
def test_mnemonic() -> str:
    return 'legal winner thank year wave sausage worth useful legal winner thank yellow'


@pytest.fixture
def _init_vault(vault_address: HexAddress, data_dir: Path, test_mnemonic: str) -> None:
    config = VaultConfig(vault=vault_address, data_dir=data_dir)
    config.save(GOERLI, test_mnemonic)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def _create_keys(
    test_mnemonic: str,
    vault_address: HexAddress,
    data_dir: Path,
    _test_keystore_password_file: Path,
    runner: CliRunner,
) -> None:
    count = 5

    result = runner.invoke(
        create_keys,
        [
            '--mnemonic',
            f'"{test_mnemonic}"',
            '--count',
            str(count),
            '--vault',
            str(vault_address),
            '--data-dir',
            str(data_dir),
        ],
    )
    assert result.exit_code == 0


@pytest.fixture
def _create_wallet(
    vault_address: HexAddress, data_dir: Path, test_mnemonic: str, runner: CliRunner
) -> None:
    result = runner.invoke(
        create_wallet,
        [
            '--mnemonic',
            f'"{test_mnemonic}"',
            '--vault',
            str(vault_address),
            '--data-dir',
            str(data_dir),
        ],
    )
    assert result.exit_code == 0


@pytest.fixture
def remote_signer_keystores_dir(temp_dir: Path) -> Path:
    return temp_dir / 'remote_signer_keystores'


@pytest.fixture
# pylint: disable-next=too-many-arguments
def _generate_key_shares(
    vault_address: HexAddress,
    data_dir: Path,
    keystores_dir: Path,
    remote_signer_keystores_dir: Path,
    execution_endpoints: str,
    runner: CliRunner,
    mocked_oracles: Oracles,
    _create_keys,
) -> None:
    with mock.patch('src.commands.generate_key_shares.get_oracles', return_value=mocked_oracles):
        result = runner.invoke(
            generate_key_shares,
            [
                '--vault',
                str(vault_address),
                '--data-dir',
                str(data_dir),
                '--execution-endpoints',
                execution_endpoints,
                '--output-dir',
                str(remote_signer_keystores_dir),
            ],
        )
        assert result.exit_code == 0


@pytest.fixture
def remote_signer_config(_generate_key_shares) -> RemoteSignerConfiguration:
    return RemoteSignerConfiguration.from_file(settings.remote_signer_config_file)


@pytest.fixture
def remote_signer_url() -> str:
    return 'http://web3signer:9000'


@pytest.fixture
def _mocked_remote_signer(
    remote_signer_keystores_dir: Path,
    _test_keystore_password: str,
    remote_signer_url: str,
    _generate_key_shares,
) -> Generator:
    _remote_signer_pubkey_privkey_mapping: dict[HexStr, BLSPrivkey] = {}

    for filename in os.listdir(remote_signer_keystores_dir):
        pubkey, priv_key = _process_keystore_file(
            KeystoreFile(name=filename, password=_test_keystore_password),
            keystore_path=remote_signer_keystores_dir,
        )
        _remote_signer_pubkey_privkey_mapping[pubkey] = priv_key

    def _mocked_remote_signer(url, **kwargs) -> CallbackResult:
        public_key_to_sign_for = url.path.split('/')[-1]

        try:
            corresponding_private_key = _remote_signer_pubkey_privkey_mapping[
                public_key_to_sign_for
            ]
        except KeyError:
            return CallbackResult(status=404, body='Not Found')

        signature = bls.Sign(
            corresponding_private_key, Web3.to_bytes(hexstr=kwargs['json']['signingRoot'])
        )

        return CallbackResult(payload={'signature': f'0x{signature.hex()}'})

    with aioresponses() as m:
        m.post(
            re.compile(f'^{remote_signer_url}/api/v1/eth2/sign/\\w{{98}}$'),
            callback=_mocked_remote_signer,
            repeat=True,
        )
        yield


@pytest.fixture
def vault_address() -> HexAddress:
    return faker.eth_address()


@pytest.fixture
def vault_dir(data_dir: Path, vault_address: HexAddress) -> Path:
    vault_dir = data_dir / vault_address.lower()
    return vault_dir


@pytest.fixture
def consensus_endpoints() -> str:
    return 'http://consensus'


@pytest.fixture
def execution_endpoints() -> str:
    return 'http://execution'


@pytest.fixture
# pylint: disable-next=too-many-arguments
def fake_settings(
    data_dir: Path,
    vault_dir: Path,
    keystores_dir: Path,
    vault_address: HexAddress,
    consensus_endpoints: str,
    execution_endpoints: str,
):
    settings.set(
        vault=vault_address,
        vault_dir=vault_dir,
        consensus_endpoints=consensus_endpoints,
        execution_endpoints=execution_endpoints,
        network=GOERLI,
        keystores_dir=str(keystores_dir),
        database_dir=str(data_dir),
    )


@pytest.fixture
def _mocked_oracle_committee(request: SubRequest) -> OracleCommittee:
    # Allow test to specify oracle_count and the threshold
    try:
        oracle_count, exit_signature_recover_threshold = request.param
    except AttributeError:
        # Fallback values if unspecified
        oracle_count = 11
        exit_signature_recover_threshold = 8

    oracle_privkeys = []
    oracle_pubkeys = []
    for i in range(oracle_count):
        oracle_privkey = ecies.PrivateKey(secret=f'{i}'.encode())
        oracle_privkeys.append(oracle_privkey)
        oracle_pubkeys.append(oracle_privkey.public_key)

    oracle_committee = OracleCommittee(
        oracle_privkeys=oracle_privkeys,
        oracle_pubkeys=oracle_pubkeys,
        exit_signature_recover_threshold=exit_signature_recover_threshold,
    )
    return oracle_committee


@pytest.fixture
def mocked_oracles(
    _mocked_oracle_committee: OracleCommittee,
) -> Oracles:
    exit_signature_recover_threshold = _mocked_oracle_committee.exit_signature_recover_threshold

    return Oracles(
        rewards_threshold=1,
        validators_threshold=1,
        exit_signature_recover_threshold=exit_signature_recover_threshold,
        # Strip first byte (04 prefix) from pubkey
        public_keys=[
            HexStr(pubkey.format(compressed=False)[1:].hex())
            for pubkey in _mocked_oracle_committee.oracle_pubkeys
        ],
        endpoints=[
            f'http://oracle-endpoint-{i}'
            for i in range(len(_mocked_oracle_committee.oracle_pubkeys))
        ],
        validators_approval_batch_limit=1,
        validators_exit_rotation_batch_limit=1,
    )


@pytest.fixture
def create_validator_keypair(
    test_mnemonic: str, vault_address: HexAddress
) -> Callable[[], tuple[BLSPrivkey, HexStr]]:
    def _generate_keypair_function() -> tuple[BLSPrivkey, HexStr]:
        """Returns a random validator keypair"""
        credential = CredentialManager.generate_credential(
            network=GOERLI,
            vault=vault_address,
            mnemonic=test_mnemonic,
            index=randint(0, 100_000),
        )

        return (BLSPrivkey(credential.private_key.to_bytes(32, 'big')), credential.public_key)

    return _generate_keypair_function
