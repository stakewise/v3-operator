import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import cached_property
from multiprocessing import Pool
from os import path
from secrets import randbits
from typing import cast

import click
import milagro_bls_binding as bls
from eth_typing import BLSPrivateKey, ChecksumAddress, HexAddress, HexStr
from py_ecc.bls import G2ProofOfPossession
from staking_deposit.key_handling.key_derivation.mnemonic import get_seed
from staking_deposit.key_handling.key_derivation.path import path_to_nodes
from staking_deposit.key_handling.key_derivation.tree import (
    derive_child_SK,
    derive_master_SK,
)
from staking_deposit.key_handling.keystore import Keystore, ScryptKeystore
from staking_deposit.settings import DEPOSIT_CLI_VERSION
from sw_utils import get_v1_withdrawal_credentials
from sw_utils.signing import (
    DepositData,
    DepositMessage,
    compute_deposit_domain,
    compute_signing_root,
)
from sw_utils.typings import Bytes32
from web3 import Web3
from web3._utils import request

from src.common.utils import chunkify
from src.config.networks import NETWORKS
from src.config.settings import DEPOSIT_AMOUNT_GWEI

# Set path as EIP-2334 format
# https://eips.ethereum.org/EIPS/eip-2334
PURPOSE = '12381'
COIN_TYPE = '3600'


@dataclass
class Credential:
    private_key: BLSPrivateKey
    network: str

    path: str | None = None
    vault: ChecksumAddress | None = None

    @cached_property
    def public_key(self) -> HexStr:
        return Web3.to_hex(G2ProofOfPossession.SkToPk(self.private_key))

    @cached_property
    def private_key_bytes(self) -> bytes:
        return self.private_key.to_bytes(32, 'big')

    @cached_property
    def amount(self) -> int:
        return DEPOSIT_AMOUNT_GWEI

    @cached_property
    def withdrawal_credentials(self) -> Bytes32:
        return get_v1_withdrawal_credentials(cast(HexAddress, self.vault))

    def save_signing_keystore(
        self, password: str, folder: str, per_keystore_password: bool = False
    ) -> str:
        keystore = self.encrypt_signing_keystore(password)
        file_name = f'keystore-{keystore.path.replace('/', '_')}-{int(time.time())}'
        file_path = path.join(folder, f'{file_name}.json')

        if per_keystore_password:
            password_file_path = path.join(folder, f'{file_name}.txt')
            with open(password_file_path, 'w', encoding='utf-8') as password_file:
                password_file.write(password)

        keystore.save(file_path)
        return file_path

    def encrypt_signing_keystore(self, password: str) -> Keystore:
        return ScryptKeystore.encrypt(
            secret=self.private_key_bytes,
            password=password,
            path=self.path,
            kdf_salt=randbits(256).to_bytes(32, 'big'),
            aes_iv=randbits(128).to_bytes(16, 'big'),
        )

    @property
    def deposit_message(self) -> DepositMessage:
        return DepositMessage(
            pubkey=Web3.to_bytes(hexstr=self.public_key),
            withdrawal_credentials=self.withdrawal_credentials,
            amount=self.amount,
        )

    @property
    def signed_deposit(self) -> DepositData:
        fork_version = NETWORKS[self.network].GENESIS_FORK_VERSION
        domain = compute_deposit_domain(fork_version)
        signing_root = compute_signing_root(self.deposit_message, domain)
        signed_deposit = DepositData(
            **self.deposit_message.as_dict(),
            # pylint: disable-next=no-member
            signature=bls.Sign(self.private_key_bytes, signing_root),
        )
        return signed_deposit

    def deposit_datum_dict(self) -> dict[str, bytes]:
        signed_deposit_datum = self.signed_deposit
        fork_version = NETWORKS[self.network].GENESIS_FORK_VERSION
        datum_dict = signed_deposit_datum.as_dict()
        datum_dict.update({'deposit_message_root': self.deposit_message.hash_tree_root})
        datum_dict.update({'deposit_data_root': signed_deposit_datum.hash_tree_root})
        datum_dict.update({'fork_version': fork_version})
        datum_dict.update({'network_name': self.network})
        datum_dict.update({'deposit_cli_version': DEPOSIT_CLI_VERSION})
        return datum_dict


class CredentialManager:
    @staticmethod
    # pylint: disable-next=too-many-arguments
    def generate_credentials(
        network: str,
        mnemonic: str,
        count: int,
        start_index: int,
        pool_size: int | None = None,
    ) -> list[Credential]:
        credentials: list[Credential] = []
        with click.progressbar(  # type: ignore
            length=count,
            label='Creating validator keys:\t\t',
            show_percent=False,
            show_pos=True,
        ) as progress_bar, Pool(processes=pool_size) as pool:

            def bar_updated(result: list) -> None:
                progress_bar.update(len(result))

            results = []
            indexes = range(start_index, start_index + count)
            for chunk_indexes in chunkify(indexes, 50):
                results.append(
                    pool.apply_async(
                        CredentialManager._generate_credentials_chunk,
                        [
                            chunk_indexes,
                            network,
                            mnemonic,
                        ],
                        callback=bar_updated,
                    )
                )

            for result in results:
                result.wait()
            for result in results:
                credentials.extend(result.get())

        return credentials

    @staticmethod
    def _generate_credentials_chunk(
        indexes: list[int],
        network: str,
        mnemonic: str,
    ) -> list[Credential]:
        # Hack to run web3 sessions in multiprocessing mode
        # pylint: disable-next=protected-access
        request._async_session_pool = ThreadPoolExecutor(max_workers=1)

        credentials: list[Credential] = []
        for index in indexes:
            credential = CredentialManager.generate_credential(network, mnemonic, index)
            credentials.append(credential)
        return credentials

    @staticmethod
    def generate_credential_first_public_key(network: str, mnemonic: str) -> str:
        return CredentialManager.generate_credential(
            network=network,
            mnemonic=mnemonic,
            index=0,
        ).public_key

    @staticmethod
    def generate_credential(network: str, mnemonic: str, index: int) -> Credential:
        """Returns the signing key of the mnemonic at a specific index."""
        seed = get_seed(mnemonic=mnemonic, password='')  # nosec
        private_key = BLSPrivateKey(derive_master_SK(seed))
        signing_key_path = f'm/{PURPOSE}/{COIN_TYPE}/{index}/0/0'
        nodes = path_to_nodes(signing_key_path)

        for node in nodes:
            private_key = BLSPrivateKey(derive_child_SK(parent_SK=private_key, index=node))

        return Credential(private_key=private_key, path=signing_key_path, network=network)

    @staticmethod
    def load_credential(
        network: str, vault: ChecksumAddress, private_key: BLSPrivateKey
    ) -> Credential:
        return Credential(private_key=private_key, network=network, vault=vault)
