import logging
from dataclasses import dataclass
from multiprocessing import Pool
from os import listdir
from os.path import isfile
from pathlib import Path
from typing import NewType

import milagro_bls_binding as bls
from eth_typing import BLSSignature, HexStr
from staking_deposit.key_handling.keystore import ScryptKeystore
from sw_utils.signing import get_exit_message_signing_root
from sw_utils.typings import ConsensusFork
from web3 import Web3

from src.common.typings import Oracles
from src.config.settings import NETWORKS, settings
from src.validators.exceptions import KeystoreException
from src.validators.keystores.base import BaseKeystore
from src.validators.signing.common import encrypt_signature
from src.validators.signing.key_shares import private_key_to_private_key_shares
from src.validators.typings import BLSPrivkey, ExitSignatureShards

logger = logging.getLogger(__name__)


@dataclass
class KeystoreFile:
    name: str
    password: str


Keystores = NewType('Keystores', dict[HexStr, BLSPrivkey])


class LocalKeystore(BaseKeystore):
    keystores: Keystores

    def __init__(self, keystores: Keystores):
        self.keystores = keystores

    @staticmethod
    async def load() -> 'LocalKeystore':
        """Extracts private keys from the keystores."""
        keystore_files = LocalKeystore.list_keystore_files()
        logger.info('Loading keystores from %s...', settings.keystores_dir)
        keystores = {}
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
                    keystores[pub_key] = priv_key
                except KeystoreException as e:
                    logger.error(e)
                    raise RuntimeError('Failed to load keystores') from e

        logger.info('Loaded %d keystores', len(keystores))
        return LocalKeystore(Keystores(keystores))

    def __bool__(self) -> bool:
        return len(self.keystores) > 0

    def __contains__(self, public_key):
        return public_key in self.keystores

    def __len__(self) -> int:
        return len(self.keystores)

    async def get_exit_signature_shards(
        self, validator_index: int, public_key: HexStr, oracles: Oracles, fork: ConsensusFork
    ) -> ExitSignatureShards:
        """Generates exit signature shards and encrypts them with oracles' public keys."""
        message = get_exit_message_signing_root(
            validator_index=validator_index,
            genesis_validators_root=settings.network_config.GENESIS_VALIDATORS_ROOT,
            fork=fork,
        )

        private_key_shares = private_key_to_private_key_shares(
            private_key=self.keystores[public_key],
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

    async def get_exit_signature(
        self, validator_index: int, public_key: HexStr, network: str, fork: ConsensusFork
    ) -> BLSSignature:
        private_key = self.keystores[public_key]

        message = get_exit_message_signing_root(
            validator_index=validator_index,
            genesis_validators_root=NETWORKS[network].GENESIS_VALIDATORS_ROOT,
            fork=fork,
        )

        return bls.Sign(private_key, message)

    @property
    def public_keys(self) -> list[HexStr]:
        return list(self.keystores.keys())

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
            res.append(KeystoreFile(name=f, password=password))

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
