import asyncio
from pathlib import Path
from random import randint
from typing import Callable
from unittest import mock

import pytest
from eth_typing import BlockNumber
from sw_utils.typings import ConsensusFork

from src.common.typings import Oracles, OraclesApproval
from src.common.utils import get_current_timestamp
from src.config.settings import settings
from src.exits.tasks import get_oracles_approval, wait_oracle_signature_update
from src.validators.signing.remote import RemoteSignerConfiguration
from src.validators.typings import ExitSignatureShards, Keystores


@pytest.mark.usefixtures('fake_settings')
class TestWaitOracleSignatureUpdate:
    async def test_normal(self):
        update_block = BlockNumber(3)
        with (
            mock.patch('asyncio.sleep'),
            mock.patch('src.exits.tasks.time.time', return_value=100),
            mock.patch(
                'src.exits.tasks._fetch_exit_signature_block', side_effect=[None, 1, 2, 3]
            ) as fetch_mock,
        ):
            await wait_oracle_signature_update(update_block, 'http://oracle', max_time=5)

        assert fetch_mock.call_count == 4

    async def test_timeout(self):
        update_block = BlockNumber(3)
        with (
            mock.patch('asyncio.sleep'),
            mock.patch('src.exits.tasks.time.time', side_effect=[100, 103, 106]),
            mock.patch(
                'src.exits.tasks._fetch_exit_signature_block', return_value=None
            ) as fetch_mock,
            pytest.raises(asyncio.TimeoutError),
        ):
            await wait_oracle_signature_update(update_block, 'http://oracle', max_time=5)

        assert fetch_mock.call_count == 2


@pytest.mark.usefixtures('fake_settings')
class TestGetOraclesApproval:
    async def test_local_keystores(
        self, mocked_oracles: Oracles, create_validator_keypair: Callable
    ):
        oracles = mocked_oracles
        test_validator_privkey, test_validator_pubkey = create_validator_keypair()
        deadline = get_current_timestamp() + oracles.signature_validity_period
        with (
            mock.patch(
                'sw_utils.consensus.ExtendedAsyncBeacon.get_consensus_fork',
                return_value=ConsensusFork(
                    version=bytes.fromhex('00000000'),
                    epoch=1,
                ),
            ),
            mock.patch(
                'src.exits.tasks.send_signature_rotation_requests',
                return_value=OraclesApproval(
                    signatures=b'', ipfs_hash='mock_ipfs_hash', deadline=deadline
                ),
            ),
        ):
            approval = await get_oracles_approval(
                oracles=oracles,
                keystores=Keystores({test_validator_pubkey: test_validator_privkey}),
                remote_signer_config=None,
                validators={123: test_validator_pubkey},
            )
            assert approval == OraclesApproval(
                signatures=b'',
                ipfs_hash='mock_ipfs_hash',
                deadline=deadline,
            )

    async def test_remote_signer(
        self,
        vault_dir: Path,
        mocked_oracles: Oracles,
        remote_signer_config: RemoteSignerConfiguration,
        remote_signer_url: str,
    ):
        oracles = mocked_oracles
        settings.remote_signer_url = remote_signer_url
        deadline = get_current_timestamp() + oracles.signature_validity_period

        with (
            mock.patch(
                'sw_utils.consensus.ExtendedAsyncBeacon.get_consensus_fork',
                return_value=ConsensusFork(
                    version=bytes.fromhex('00000001'),
                    epoch=1,
                ),
            ),
            mock.patch(
                'src.exits.tasks.get_exit_signature_shards_remote_signer',
                return_value=ExitSignatureShards(
                    public_keys=[],
                    exit_signatures=[],
                ),
            ),
            mock.patch(
                'src.exits.tasks.send_signature_rotation_requests',
                return_value=OraclesApproval(
                    signatures=b'', ipfs_hash='mock_ipfs_hash', deadline=deadline
                ),
            ),
        ):
            approval = await get_oracles_approval(
                oracles=oracles,
                keystores=Keystores(dict()),
                remote_signer_config=remote_signer_config,
                validators={
                    randint(0, int(1e6)): pubkey
                    for pubkey in remote_signer_config.pubkeys_to_shares.keys()
                },
            )

            assert approval == OraclesApproval(
                signatures=b'',
                ipfs_hash='mock_ipfs_hash',
                deadline=deadline,
            )
