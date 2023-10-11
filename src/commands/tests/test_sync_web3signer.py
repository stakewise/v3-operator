import os
from unittest.mock import patch

from asyncclick.testing import CliRunner
from eth_typing import BLSPrivateKey
from eth_utils import add_0x_prefix
from py_ecc.bls import G2ProofOfPossession
from staking_deposit.key_handling.key_derivation.mnemonic import get_seed
from staking_deposit.key_handling.key_derivation.path import path_to_nodes
from staking_deposit.key_handling.key_derivation.tree import (
    derive_child_SK,
    derive_master_SK,
)
from web3 import Web3

from src.commands.sync_web3signer import sync_web3signer
from src.common.contrib import bytes_to_str
from src.key_manager.encryptor import Encryptor
from src.key_manager.typings import DatabaseKeyRecord

w3 = Web3()
PURPOSE = '12381'
COIN_TYPE = '3600'


class TestSyncWeb3signer:
    async def test_basic(self):
        db_url = 'postgresql://username:pass@hostname/dbname'
        keys_count = 3
        encryptor = Encryptor()

        # pylint: disable-next=line-too-long
        mnemonic = 'fluid inmate install dash among sing found brief fork actual box tonight entire you intact camera stuff main cram alpha clog educate gown tribe'
        private_keys, db_records = _generate_keys(
            mnemonic=mnemonic, encryptor=encryptor, keys_count=keys_count
        )

        runner = CliRunner()
        args = [
            '--db-url',
            db_url,
            '--decryption-key-env',
            'DECRYPT_ENV',
            '--output-dir',
            './web3signer',
        ]

        with runner.isolated_filesystem(), patch(
            'src.commands.sync_web3signer.check_db_connection'
        ), patch(
            'src.commands.sync_web3signer.Database.fetch_keys',
            return_value=db_records,
        ), patch.dict(
            os.environ, {'DECRYPT_ENV': encryptor.str_key}
        ):
            result = await runner.invoke(sync_web3signer, args)
            assert result.exit_code == 0
            output = f'Web3Signer now uses {len(db_records)} private keys.\n'
            assert output.strip() == result.output.strip()

            for index, private_key in enumerate(private_keys):
                key_hex = Web3.to_hex(int(private_key))
                with open(f'./web3signer/key_{index}.yaml', encoding='utf-8') as f:
                    s = f"""keyType: BLS
privateKey: \'{add_0x_prefix(key_hex)}\'
type: file-raw"""
                    s += '\n'
                    assert f.read() == s

            # second run
            result = await runner.invoke(sync_web3signer, args)

            assert result.exit_code == 0
            output = 'Keys already synced to the last version.\n'
            assert output.strip() == result.output.strip()


def _generate_keys(
    mnemonic, encryptor, keys_count
) -> tuple[list[BLSPrivateKey], list[DatabaseKeyRecord]]:
    private_keys, db_records = [], []

    for index in range(keys_count):
        seed = get_seed(mnemonic=mnemonic, password='')  # nosec
        private_key = BLSPrivateKey(derive_master_SK(seed))
        signing_key_path = f'm/{PURPOSE}/{COIN_TYPE}/{index}/0/0'
        nodes = path_to_nodes(signing_key_path)

        for node in nodes:
            private_key = BLSPrivateKey(derive_child_SK(parent_SK=private_key, index=node))

        encrypted_private_key, nonce = encryptor.encrypt(str(private_key))

        private_keys.append(private_key)
        db_records.append(
            DatabaseKeyRecord(
                public_key=w3.to_hex(G2ProofOfPossession.SkToPk(private_key)),
                private_key=bytes_to_str(encrypted_private_key),
                nonce=bytes_to_str(nonce),
            )
        )
    return private_keys, db_records
