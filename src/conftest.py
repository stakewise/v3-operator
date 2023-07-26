from pathlib import Path

import pytest
from sw_utils.tests import faker

from src.config.networks import GOERLI
from src.config.settings import settings


@pytest.fixture
def fake_settings():
    data_dir = Path('/tmp/stakewise')
    vault = faker.eth_address()
    vault_dir = data_dir / vault

    consensus_endpoints = 'http://consensus'
    execution_endpoints = 'http://execution'

    settings.set(
        vault=vault,
        vault_dir=vault_dir,
        consensus_endpoints=consensus_endpoints,
        execution_endpoints=execution_endpoints,
        network=GOERLI,
        harvest_vault=None,
        verbose=None,
        metrics_host=None,
        metrics_port=None,
        deposit_data_file=None,
        keystores_dir=None,
        keystores_password_file=None,
        hot_wallet_file=None,
        hot_wallet_password_file=None,
        max_fee_per_gas_gwei=None,
        database_dir=data_dir,
    )
