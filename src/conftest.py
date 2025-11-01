from pathlib import Path
from random import randint
from tempfile import TemporaryDirectory
from typing import Callable, Generator

import ecies
import pytest
from _pytest.fixtures import SubRequest
from click.testing import CliRunner
from eth_typing import HexAddress, HexStr
from sw_utils.tests import faker
from sw_utils.tests.factories import get_mocked_protocol_config
from sw_utils.typings import Oracle, ProtocolConfig

from src.commands.create_keys import create_keys
from src.commands.create_wallet import create_wallet
from src.commands.setup_remote_signer import setup_remote_signer
from src.common.clients import setup_clients
from src.common.credentials import CredentialManager
from src.config.config import OperatorConfig
from src.config.networks import HOODI, NETWORKS
from src.config.settings import settings
from src.validators.keystores.remote import RemoteSignerKeystore
from src.validators.keystores.tests.test_fixtures.hashi_vault import (
    hashi_vault_url,
    mocked_hashi_vault,
)
from src.validators.keystores.tests.test_fixtures.remote_signer import (
    mocked_remote_signer,
    remote_signer_url,
)
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
def vault_address() -> HexAddress:
    return faker.eth_address()


@pytest.fixture
def vault_dir(data_dir: Path, vault_address: HexAddress) -> Path:
    vault_dir = data_dir / vault_address.lower()
    return vault_dir


@pytest.fixture
def keystores_dir(vault_dir: Path, _init_config) -> Path:
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
def _init_config(vault_address: HexAddress, data_dir: Path, test_mnemonic: str) -> None:
    config = OperatorConfig(vault=vault_address, data_dir=data_dir)
    config.save(HOODI, test_mnemonic)


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
            '--concurrency',
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
def _setup_remote_signer(
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
        setup_remote_signer,
        [
            '--vault',
            str(vault_address),
            '--remote-signer-url',
            remote_signer_url,
            '--data-dir',
            str(data_dir),
        ],
        input='y\n',
    )
    assert result.exit_code == 0


@pytest.fixture
async def remote_signer_keystore(_setup_remote_signer) -> RemoteSignerKeystore:
    return await RemoteSignerKeystore.load()


@pytest.fixture
def vault_address() -> HexAddress:
    return faker.eth_address()


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
        network=HOODI,
        keystores_dir=str(keystores_dir),
        database_dir=str(data_dir),
        max_validator_balance_gwei=NETWORKS[HOODI].MAX_VALIDATOR_BALANCE_GWEI,
    )


@pytest.fixture
async def setup_test_clients():
    await setup_clients()


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
def create_validator_keypair(test_mnemonic: str) -> Callable[[], tuple[BLSPrivkey, HexStr]]:
    def _generate_keypair_function() -> tuple[BLSPrivkey, HexStr]:
        """Returns a random validator keypair"""
        credential = CredentialManager.generate_credential(
            network=HOODI,
            mnemonic=test_mnemonic,
            index=randint(0, 100_000),
        )

        return (BLSPrivkey(credential.private_key.to_bytes(32, 'big')), credential.public_key)

    return _generate_keypair_function
