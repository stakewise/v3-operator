from pathlib import Path
from random import randint
from typing import Callable
from unittest import mock

import pytest
from eth_typing import ChecksumAddress
from sw_utils.typings import ConsensusFork, ProtocolConfig

from src.common.utils import get_current_timestamp
from src.config.settings import settings
from src.exits.tasks import _get_oracles_request
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
        vault_dir: Path,
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
