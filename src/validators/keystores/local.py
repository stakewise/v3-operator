import logging
from dataclasses import dataclass
from multiprocessing import Pool
from os import walk
from pathlib import Path
from typing import NewType

import milagro_bls_binding as bls
from eth_typing import BLSPrivateKey, BLSSignature, HexStr
from eth_utils import add_0x_prefix
from staking_deposit.key_handling.keystore import ScryptKeystore
from sw_utils.signing import get_exit_message_signing_root
from sw_utils.typings import ConsensusFork
from web3 import Web3

from src.common.credentials import CredentialManager
from src.config.settings import settings
from src.validators.exceptions import KeystoreException
from src.validators.keystores.base import BaseKeystore
from src.validators.typings import BLSPrivkey

logger = logging.getLogger(__name__)


@dataclass
class KeystoreFile:
    name: str
    password: str
    file: Path
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
        keystores_data = []
        with Pool(processes=settings.concurrency) as pool:
            # pylint: disable-next=unused-argument
            def _stop_pool(*args, **kwargs):  # type: ignore
                pool.close()

            results = [
                pool.apply_async(
                    LocalKeystore._process_keystore_file,
                    (keystore_file,),
                    error_callback=_stop_pool,
                )
                for keystore_file in keystore_files
            ]
            for result in results:
                result.wait()
                try:
                    keystores_data.append(result.get())
                except KeystoreException as e:
                    logger.error(e)
                    raise RuntimeError('Failed to load keys') from e

        keys: dict[HexStr, BLSPrivkey] = {}
        # sort by index to have a deterministic order
        for pub_key, priv_key, _ in sorted(keystores_data, key=lambda x: x[2]):
            keys[pub_key] = priv_key

        logger.info('Loaded %d keys', len(keys))
        return LocalKeystore(Keys(keys))

    def __bool__(self) -> bool:
        return len(self.keys) > 0

    def __contains__(self, public_key: HexStr) -> bool:
        return public_key in self.keys

    def __len__(self) -> int:
        return len(self.keys)

    async def get_deposit_data(self, public_key: HexStr, amount: int) -> dict:
        private_key = self.keys[public_key]
        credential = CredentialManager.load_credential(
            network=settings.network,
            private_key=BLSPrivateKey(Web3.to_int(private_key)),
            vault=settings.vault,
            validator_type=settings.validator_type,
        )

        return credential.get_deposit_datum_dict(amount)

    async def get_exit_signature(
        self, validator_index: int, public_key: HexStr, fork: ConsensusFork | None = None
    ) -> BLSSignature:
        fork = fork or settings.network_config.SHAPELLA_FORK

        private_key = self.keys[public_key]

        message = get_exit_message_signing_root(
            validator_index=validator_index,
            genesis_validators_root=settings.network_config.GENESIS_VALIDATORS_ROOT,
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

        for current_path, _, files in walk(keystores_dir):
            for f in files:
                file_path = Path(current_path) / f
                if not (file_path.is_file() and f.startswith('keystore') and f.endswith('.json')):
                    continue

                # check for password file in the keystores_password_dir
                password_file = keystores_password_dir / f.replace('.json', '.txt')
                if not password_file.is_file():
                    # check for password file in the same directory as the keystore file
                    password_file = Path(current_path) / f.replace('.json', '.txt')

                if not password_file.is_file():
                    # use password file from the keystores_password_file setting
                    password_file = keystores_password_file

                password = LocalKeystore._load_keystores_password(password_file)
                res.append(
                    KeystoreFile(
                        name=f, file=file_path, password=password, password_file=password_file
                    )
                )
        return res

    @staticmethod
    def _process_keystore_file(keystore_file: KeystoreFile) -> tuple[HexStr, BLSPrivkey, int]:
        file_name = keystore_file.name
        keystores_password = keystore_file.password
        try:
            keystore = ScryptKeystore.from_file(keystore_file.file)
        except BaseException as e:
            raise KeystoreException(f'Invalid keystore format in file "{file_name}"') from e

        try:
            private_key = BLSPrivkey(keystore.decrypt(keystores_password))
        except BaseException as e:
            raise KeystoreException(f'Invalid password for keystore "{file_name}"') from e
        public_key = Web3.to_hex(bls.SkToPk(private_key))

        # extract index from path: m/12381/3600/<index>/0/0
        index = int(keystore.path.split('/')[3])
        return public_key, private_key, index

    @staticmethod
    def _load_keystores_password(password_path: Path) -> str:
        with open(password_path, 'r', encoding='utf-8') as f:
            return f.read().strip()

    @staticmethod
    def parse_keystore_file(keystore_file: KeystoreFile) -> tuple[int, HexStr]:
        """
        Extracts the key index and public key from a keystore file.
        Does not decrypt the keystore.
        """
        keystore = ScryptKeystore.from_file(keystore_file.file)

        # extract index from path: m/12381/3600/<index>/0/0
        key_index = int(keystore.path.split('/')[-3])
        public_key = add_0x_prefix(HexStr(keystore.pubkey))

        return key_index, public_key
