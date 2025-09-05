import logging
from dataclasses import dataclass
from multiprocessing import Pool
from os import listdir
from os.path import isfile
from pathlib import Path
from typing import NewType

import milagro_bls_binding as bls
from eth_typing import BLSPrivateKey, BLSSignature, ChecksumAddress, HexStr
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
    path: Path
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

    async def get_deposit_data(
        self, public_key: HexStr, amount: int, vault_address: ChecksumAddress
    ) -> dict:
        private_key = self.keys[public_key]
        credential = CredentialManager.load_credential(
            network=settings.network,
            private_key=BLSPrivateKey(Web3.to_int(private_key)),
            vault=vault_address,
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
        for f in listdir(keystores_dir):
            if not (isfile(keystores_dir / f) and f.startswith('keystore') and f.endswith('.json')):
                continue

            password_file = keystores_password_dir / f.replace('.json', '.txt')
            if not isfile(password_file):
                password_file = keystores_password_file

            password = LocalKeystore._load_keystores_password(password_file)
            res.append(
                KeystoreFile(
                    name=f, path=keystores_dir / f, password=password, password_file=password_file
                )
            )

        return res

    @staticmethod
    def _process_keystore_file(keystore_file: KeystoreFile) -> tuple[HexStr, BLSPrivkey, int]:
        keystores_password = keystore_file.password

        try:
            keystore = ScryptKeystore.from_file(keystore_file.path)
        except BaseException as e:
            raise KeystoreException(
                f'Invalid keystore format in file "{keystore_file.name}"'
            ) from e

        try:
            private_key = BLSPrivkey(keystore.decrypt(keystores_password))
        except BaseException as e:
            raise KeystoreException(f'Invalid password for keystore "{keystore_file.name}"') from e
        public_key = Web3.to_hex(bls.SkToPk(private_key))
        return public_key, private_key, int(keystore.path.split('/')[3])

    @staticmethod
    def _load_keystores_password(password_path: Path) -> str:
        with open(password_path, 'r', encoding='utf-8') as f:
            return f.read().strip()
