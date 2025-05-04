import contextlib
from pathlib import Path
from random import randint
from typing import Callable
from unittest import mock
from unittest.mock import AsyncMock

import pytest
from eth_typing import ChecksumAddress
from sw_utils.typings import ConsensusFork, ProtocolConfig

from src.common.utils import get_current_timestamp
from src.config.settings import settings
from src.exits.tasks import _fetch_last_update_block, _get_oracles_request
from src.validators.keystores.local import Keys, LocalKeystore
from src.validators.keystores.remote import RemoteSignerKeystore


@pytest.mark.usefixtures('fake_settings')
class TestGetOraclesRequest:
    async def test_local_keystores(
        self,
        mocked_protocol_config: ProtocolConfig,
        vault_address: ChecksumAddress,
        create_validator_keypair: Callable,
    ):
        protocol_config = mocked_protocol_config
        test_validator_privkey, test_validator_pubkey = create_validator_keypair()
        deadline = get_current_timestamp() + protocol_config.signature_validity_period
        with (
            mock.patch(
                'sw_utils.consensus.ExtendedAsyncBeacon.get_consensus_fork',
                return_value=ConsensusFork(
                    version=bytes.fromhex('00000000'),
                    epoch=1,
                ),
            ),
        ):
            request = await _get_oracles_request(
                protocol_config=protocol_config,
                keystore=LocalKeystore(Keys({test_validator_pubkey: test_validator_privkey})),
                validators={123: test_validator_pubkey},
            )
            assert request.vault_address == vault_address
            assert request.public_keys == [test_validator_pubkey]
            assert request.deadline == deadline

    async def test_remote_signer(
        self,
        config_dir: Path,
        vault_address: ChecksumAddress,
        mocked_protocol_config: ProtocolConfig,
        remote_signer_keystore: RemoteSignerKeystore,
        remote_signer_url: str,
    ):
        protocol_config = mocked_protocol_config
        settings.remote_signer_url = remote_signer_url
        deadline = get_current_timestamp() + protocol_config.signature_validity_period

        with (
            mock.patch(
                'sw_utils.consensus.ExtendedAsyncBeacon.get_consensus_fork',
                return_value=ConsensusFork(
                    version=bytes.fromhex('00000001'),
                    epoch=1,
                ),
            ),
        ):
            validators = {
                randint(0, int(1e6)): pubkey for pubkey in remote_signer_keystore.public_keys
            }
            request = await _get_oracles_request(
                protocol_config=protocol_config,
                keystore=remote_signer_keystore,
                validators=validators,
            )

            assert request.vault_address == vault_address
            assert (
                request.public_keys
                == list(validators.values())[: protocol_config.validators_exit_rotation_batch_limit]
            )
            assert request.deadline == deadline


@pytest.mark.usefixtures('fake_settings')
class TestFetchLastExitSignatureUpdateBlock:
    async def test_normal(self):
        get_event_func = 'src.exits.tasks.keeper_contract.get_exit_signatures_updated_event'

        # no events, checkpoint moved from None to 8
        with (
            mock.patch(get_event_func, return_value=None) as get_event_mock,
            patch_latest_block(8),
        ):
            last_update_block = await _fetch_last_update_block()

        assert last_update_block is None
        get_event_mock.assert_called_once_with(vault=settings.vault, from_block=None, to_block=8)

        # no events, checkpoint moved to 9
        with (
            mock.patch(get_event_func, return_value=None) as get_event_mock,
            patch_latest_block(9),
        ):
            last_update_block = await _fetch_last_update_block()

        assert last_update_block is None
        get_event_mock.assert_called_once_with(vault=settings.vault, from_block=9, to_block=9)

        # event is found, checkpoint moved to 15
        with (
            mock.patch(get_event_func, return_value=dict(blockNumber=11)) as get_event_mock,
            patch_latest_block(15),
        ):
            last_update_block = await _fetch_last_update_block()

        assert last_update_block == 11
        get_event_mock.assert_called_once_with(vault=settings.vault, from_block=10, to_block=15)

        # no events, checkpoint moved to 20
        with (
            mock.patch(get_event_func, return_value=None) as get_event_mock,
            patch_latest_block(20),
        ):
            last_update_block = await _fetch_last_update_block()

        assert last_update_block == 11
        get_event_mock.assert_called_once_with(vault=settings.vault, from_block=16, to_block=20)


@contextlib.contextmanager
def patch_latest_block(block_number):
    with mock.patch('src.exits.tasks.execution_client', new=AsyncMock()) as execution_client_mock:
        execution_client_mock.eth.get_block_number.return_value = block_number
        yield
