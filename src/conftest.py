from pathlib import Path
from random import randint
from tempfile import TemporaryDirectory
from typing import Callable, Generator
from unittest import mock

import ecies
import pytest
from _pytest.fixtures import SubRequest
from click.testing import CliRunner
from Cryptodome.Protocol.KDF import scrypt as raw_scrypt
from eth_typing import HexAddress, HexStr
from sw_utils.tests import faker
from sw_utils.tests.factories import get_mocked_protocol_config
from sw_utils.typings import Oracle, ProtocolConfig

from src.commands.create_keys import create_keys
from src.commands.create_wallet import create_wallet
from src.commands.remote_signer_setup import remote_signer_setup
from src.common.credentials import CredentialManager, ScryptKeystore
from src.common.vault_config import VaultConfig
from src.config.networks import HOLESKY
from src.config.settings import settings
from src.test_fixtures.hashi_vault import hashi_vault_url, mocked_hashi_vault  # noqa
from src.test_fixtures.remote_signer import mocked_remote_signer, remote_signer_url
from src.validators.keystores.remote import RemoteSignerKeystore
from src.validators.signing.tests.oracle_functions import OracleCommittee
from src.validators.typings import BLSPrivkey


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
    config.save(HOLESKY, test_mnemonic)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _scrypt_without_validation(
    *, password: str, salt: str, n: int, r: int, p: int, dklen: int
) -> bytes:
    """
    Shortened version of `staking_deposit.utils.crypto.scrypt`.
    All validations are deleted to allow small number of hash iterations (`n`).
    The function is not secure. Use it in tests only.
    """
    res = raw_scrypt(password=password, salt=salt, key_len=dklen, N=n, r=r, p=p)
    return res if isinstance(res, bytes) else res[0]  # PyCryptodome can return Tuple[bytes]


@pytest.fixture
def mock_scrypt_keystore():
    """
    Decreases number of iterations of password hashing. Original value is ~200k.
    This improves speed of keystore encryption.
    Not secure.
    """
    with mock.patch.dict(ScryptKeystore.crypto.kdf.params, {'n': 2}), mock.patch(
        'staking_deposit.key_handling.keystore.scrypt', new=_scrypt_without_validation
    ):
        yield


@pytest.fixture
def _create_keys(
    test_mnemonic: str,
    vault_address: HexAddress,
    data_dir: Path,
    _test_keystore_password_file: Path,
    mock_scrypt_keystore,
    runner: CliRunner,
) -> None:
    count = 3

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
            '--pool-size',
            '1',
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
def _remote_signer_setup(
    vault_address: HexAddress,
    data_dir: Path,
    keystores_dir: Path,
    remote_signer_url: str,
    execution_endpoints: str,
    runner: CliRunner,
    mocked_protocol_config: ProtocolConfig,
    mocked_remote_signer,
    _create_keys,
) -> None:
    result = runner.invoke(
        remote_signer_setup,
        [
            '--vault',
            str(vault_address),
            '--remote-signer-url',
            remote_signer_url,
            '--data-dir',
            str(data_dir),
        ],
    )
    assert result.exit_code == 0


@pytest.fixture
async def remote_signer_keystore(_remote_signer_setup) -> RemoteSignerKeystore:
    return await RemoteSignerKeystore.load()


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
        network=HOLESKY,
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
        # Intentionally using lower values here to speed up tests
        oracle_count = 3
        exit_signature_recover_threshold = 2

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
def mocked_protocol_config(
    _mocked_oracle_committee: OracleCommittee,
) -> ProtocolConfig:
    exit_signature_recover_threshold = _mocked_oracle_committee.exit_signature_recover_threshold
    oracles = []
    for index, pub_key in enumerate(_mocked_oracle_committee.oracle_pubkeys):
        oracle = Oracle(
            public_key=HexStr(pub_key.format(compressed=False)[1:].hex()),
            endpoints=[f'http://oracle-endpoint-{index}'],
        )
        oracles.append(oracle)
    return get_mocked_protocol_config(
        oracles=oracles,
        exit_signature_recover_threshold=exit_signature_recover_threshold,
        validators_approval_batch_limit=1,
        validators_exit_rotation_batch_limit=2,
        signature_validity_period=60,
    )


@pytest.fixture
def create_validator_keypair(
    test_mnemonic: str, vault_address: HexAddress
) -> Callable[[], tuple[BLSPrivkey, HexStr]]:
    def _generate_keypair_function() -> tuple[BLSPrivkey, HexStr]:
        """Returns a random validator keypair"""
        credential = CredentialManager.generate_credential(
            network=HOLESKY,
            vault=vault_address,
            mnemonic=test_mnemonic,
            index=randint(0, 100_000),
        )

        return (BLSPrivkey(credential.private_key.to_bytes(32, 'big')), credential.public_key)

    return _generate_keypair_function
