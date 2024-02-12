import logging
from dataclasses import dataclass
from multiprocessing import Pool
from os import listdir
from os.path import isfile
from pathlib import Path
from typing import NewType

import milagro_bls_binding as bls
from eth_typing import BLSPubkey, BLSSignature, HexStr
from staking_deposit.key_handling.keystore import ScryptKeystore
from sw_utils.signing import get_exit_message_signing_root
from sw_utils.typings import ConsensusFork
from web3 import Web3

from src.common.typings import Oracles
from src.config.settings import NETWORKS, settings
from src.validators.exceptions import KeystoreException
from src.validators.keystores.base import BaseKeystore
from src.validators.signing.common import encrypt_signature
from src.validators.signing.key_shares import (
    bls_signature_and_public_key_to_shares,
    private_key_to_private_key_shares,
)
from src.validators.typings import BLSPrivkey, ExitSignatureShards

logger = logging.getLogger(__name__)


@dataclass
class KeystoreFile:
    name: str
    password: str
    password_file: Path


Keys = NewType('Keys', dict[HexStr, BLSPrivkey])


class LocalKeystore(BaseKeystore):
    keys: Keys

    def __init__(self, keys: Keys):
        self.keys = keys

    @staticmethod
    async def load() -> 'LocalKeystore':
        """Extracts private keys from the keys."""
        keystore_files = LocalKeystore.list_keystore_files()
        logger.info('Loading keys from %s...', settings.keystores_dir)
        keys = {}
        with Pool(processes=settings.pool_size) as pool:
            # pylint: disable-next=unused-argument
            def _stop_pool(*args, **kwargs):
                pool.close()

            results = [
                pool.apply_async(
                    LocalKeystore._process_keystore_file,
                    (keystore_file, settings.keystores_dir),
                    error_callback=_stop_pool,
                )
                for keystore_file in keystore_files
            ]
            for result in results:
                result.wait()
                try:
                    pub_key, priv_key = result.get()
                    keys[pub_key] = priv_key
                except KeystoreException as e:
                    logger.error(e)
                    raise RuntimeError('Failed to load keys') from e

        logger.info('Loaded %d keys', len(keys))
        return LocalKeystore(Keys(keys))

    def __bool__(self) -> bool:
        return len(self.keys) > 0

    def __contains__(self, public_key):
        return public_key in self.keys

    def __len__(self) -> int:
        return len(self.keys)

    async def get_exit_signature_shards(
        self, validator_index: int, public_key: HexStr, oracles: Oracles, fork: ConsensusFork
    ) -> ExitSignatureShards:
        """
        * generates exit signature shards,
        * generates public key shards
        * encrypts exit signature shards with oracles' public keys.
        """
        message = get_exit_message_signing_root(
            validator_index=validator_index,
            genesis_validators_root=settings.network_config.GENESIS_VALIDATORS_ROOT,
            fork=fork,
        )

        private_key_shares = private_key_to_private_key_shares(
            private_key=self.keys[public_key],
            threshold=oracles.exit_signature_recover_threshold,
            total=len(oracles.public_keys),
        )
        exit_signature_shards: list[HexStr] = []
        for bls_priv_key, oracle_pubkey in zip(private_key_shares, oracles.public_keys):
            exit_signature_shards.append(
                encrypt_signature(oracle_pubkey, bls.Sign(bls_priv_key, message))
            )

        return ExitSignatureShards(
            public_keys=[Web3.to_hex(bls.SkToPk(priv_key)) for priv_key in private_key_shares],
            exit_signatures=exit_signature_shards,
        )

    @staticmethod
    async def get_exit_signature_shards_without_keystore(
        validator_index: int,
        public_key: HexStr,
        oracles: Oracles,
        fork: ConsensusFork,
        exit_signature: BLSSignature,
    ) -> ExitSignatureShards:
        """
        Similar to `get_exit_signature_shards`, but keystores (private keys) are not used.
        The function requires `exit_signature` is generated before and passed as argument.

        * generates exit signature shards,
        * generates public key shards
        * encrypts exit signature shards with oracles' public keys.
        """
        message = get_exit_message_signing_root(
            validator_index=validator_index,
            genesis_validators_root=settings.network_config.GENESIS_VALIDATORS_ROOT,
            fork=fork,
        )

        public_key_bytes = BLSPubkey(Web3.to_bytes(hexstr=public_key))
        threshold = oracles.exit_signature_recover_threshold
        total = len(oracles.public_keys)

        exit_signature_shares, public_key_shares = bls_signature_and_public_key_to_shares(
            message, exit_signature, public_key_bytes, threshold, total
        )

        encrypted_exit_signature_shares: list[HexStr] = []

        for exit_signature_share, oracle_pubkey in zip(exit_signature_shares, oracles.public_keys):
            encrypted_exit_signature_shares.append(
                encrypt_signature(oracle_pubkey, exit_signature_share)
            )

        return ExitSignatureShards(
            public_keys=[Web3.to_hex(p) for p in public_key_shares],
            exit_signatures=encrypted_exit_signature_shares,
        )

    async def get_exit_signature(
        self, validator_index: int, public_key: HexStr, network: str, fork: ConsensusFork
    ) -> BLSSignature:
        private_key = self.keys[public_key]

        message = get_exit_message_signing_root(
            validator_index=validator_index,
            genesis_validators_root=NETWORKS[network].GENESIS_VALIDATORS_ROOT,
            fork=fork,
        )

        return bls.Sign(private_key, message)

    @property
    def public_keys(self) -> list[HexStr]:
        return list(self.keys.keys())

    @staticmethod
    def list_keystore_files() -> list[KeystoreFile]:
        keystores_dir = settings.keystores_dir
        keystores_password_dir = settings.keystores_password_dir
        keystores_password_file = settings.keystores_password_file

        res: list[KeystoreFile] = []
        for f in listdir(keystores_dir):
            if not (isfile(keystores_dir / f) and f.startswith('keystore') and f.endswith('.json')):
                continue

            password_file = keystores_password_dir / f.replace('.json', '.txt')
            if not isfile(password_file):
                password_file = keystores_password_file

            password = LocalKeystore._load_keystores_password(password_file)
            res.append(KeystoreFile(name=f, password=password, password_file=password_file))

        return res

    @staticmethod
    def _process_keystore_file(
        keystore_file: KeystoreFile, keystore_path: Path
    ) -> tuple[HexStr, BLSPrivkey]:
        file_name = keystore_file.name
        keystores_password = keystore_file.password
        file_path = keystore_path / file_name

        try:
            keystore = ScryptKeystore.from_file(file_path)
        except BaseException as e:
            raise KeystoreException(f'Invalid keystore format in file "{file_name}"') from e

        try:
            private_key = BLSPrivkey(keystore.decrypt(keystores_password))
        except BaseException as e:
            raise KeystoreException(f'Invalid password for keystore "{file_name}"') from e
        public_key = Web3.to_hex(bls.SkToPk(private_key))
        return public_key, private_key

    @staticmethod
    def _load_keystores_password(password_path: Path) -> str:
        with open(password_path, 'r', encoding='utf-8') as f:
            return f.read().strip()
