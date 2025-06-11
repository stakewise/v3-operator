import dataclasses
import logging
from dataclasses import dataclass
from typing import cast

import milagro_bls_binding as bls
from aiohttp import ClientSession, ClientTimeout
from eth_typing import BLSPubkey, BLSSignature, ChecksumAddress, HexAddress, HexStr
from sw_utils import get_exit_message_signing_root, get_v1_withdrawal_credentials
from sw_utils.common import urljoin
from sw_utils.signing import DepositMessage as SerializableDepositMessage
from sw_utils.signing import compute_deposit_domain, compute_signing_root
from sw_utils.typings import ConsensusFork
from web3 import Web3

from src.config.networks import NETWORKS
from src.config.settings import DEPOSIT_AMOUNT_GWEI, REMOTE_SIGNER_TIMEOUT, settings
from src.validators.keystores.base import BaseKeystore

logger = logging.getLogger(__name__)


@dataclass
class Fork:
    previous_version: HexStr
    current_version: HexStr
    epoch: int


@dataclass
class ForkInfo:
    fork: Fork
    genesis_validators_root: HexStr


@dataclass
class VoluntaryExitMessage:
    epoch: int
    validator_index: int


@dataclass
class VoluntaryExitRequestModel:
    fork_info: ForkInfo
    signing_root: HexStr
    type: str
    voluntary_exit: VoluntaryExitMessage


@dataclass
class DepositMessage:
    pubkey: HexStr
    withdrawal_credentials: HexStr
    amount: str
    fork_version: HexStr


@dataclass
class DepositRequestModel:
    deposit: DepositMessage
    signing_root: HexStr
    type: str


class RemoteSignerKeystore(BaseKeystore):
    def __init__(self, public_keys: list[HexStr]):
        self._public_keys = public_keys

    @staticmethod
    async def load() -> 'BaseKeystore':
        public_keys = await RemoteSignerKeystore._get_remote_signer_public_keys()
        return RemoteSignerKeystore(public_keys)

    def __bool__(self) -> bool:
        return bool(self._public_keys)

    def __len__(self) -> int:
        return len(self._public_keys)

    def __contains__(self, public_key: HexStr) -> bool:
        return public_key in self._public_keys

    @property
    def public_keys(self) -> list[HexStr]:
        return self._public_keys

    async def get_validator_deposits(
        self,
        public_keys: list[HexStr],
        vault_address: ChecksumAddress,
    ) -> list[dict]:
        fork_version = NETWORKS[settings.network].GENESIS_FORK_VERSION
        amount = DEPOSIT_AMOUNT_GWEI
        withdrawal_credentials = get_v1_withdrawal_credentials(cast(HexAddress, vault_address))
        deposit_data = []
        for public_key in public_keys:
            signing_root = self._get_deposit_signing_root(
                public_key=BLSPubkey(Web3.to_bytes(hexstr=public_key)),
                withdrawal_credentials=withdrawal_credentials,
                amount=amount,
                fork_version=fork_version,
            )
            signature = self._sign_deposit_data_request(
                public_key=public_key,
                withdrawal_credentials=withdrawal_credentials,
                amount=amount,
                signing_root=signing_root,
                fork_version=fork_version,
            )
            deposit_data.append(
                {
                    'pubkey': public_key,
                    'withdrawal_credentials': withdrawal_credentials,
                    'amount': amount,
                    'signature': signature,
                }
            )
        return deposit_data

    async def get_exit_signature(
        self, validator_index: int, public_key: HexStr, fork: ConsensusFork | None = None
    ) -> BLSSignature:
        fork = fork or settings.network_config.SHAPELLA_FORK

        message = get_exit_message_signing_root(
            validator_index=validator_index,
            genesis_validators_root=settings.network_config.GENESIS_VALIDATORS_ROOT,
            fork=fork,
        )
        public_key_bytes = BLSPubkey(Web3.to_bytes(hexstr=public_key))

        exit_signature = await self._sign_exit_request(
            public_key_bytes, validator_index, fork, message
        )

        bls.Verify(BLSPubkey(Web3.to_bytes(hexstr=public_key)), message, exit_signature)
        return exit_signature

    @staticmethod
    async def _get_remote_signer_public_keys() -> list[HexStr]:
        signer_base_url = cast(
            str, settings.remote_signer_public_keys_url or settings.remote_signer_url
        )

        signer_url = urljoin(signer_base_url, '/api/v1/eth2/publicKeys')
        async with ClientSession(timeout=ClientTimeout(REMOTE_SIGNER_TIMEOUT)) as session:
            response = await session.get(signer_url)

            response.raise_for_status()
            return await response.json()

    @staticmethod
    async def _sign_exit_request(
        public_key: BLSPubkey,
        validator_index: int,
        fork: ConsensusFork,
        message: bytes,
    ) -> BLSSignature:
        data = VoluntaryExitRequestModel(
            fork_info=ForkInfo(
                fork=Fork(
                    previous_version=HexStr(fork.version.hex()),
                    current_version=HexStr(fork.version.hex()),
                    epoch=fork.epoch,
                ),
                genesis_validators_root=HexStr(
                    settings.network_config.GENESIS_VALIDATORS_ROOT.hex()
                ),
            ),
            signing_root=HexStr(message.hex()),
            type='VOLUNTARY_EXIT',
            voluntary_exit=VoluntaryExitMessage(epoch=fork.epoch, validator_index=validator_index),
        )

        signer_base_url = cast(str, settings.remote_signer_url)
        signer_url = urljoin(signer_base_url, f'/api/v1/eth2/sign/0x{public_key.hex()}')

        async with ClientSession(timeout=ClientTimeout(REMOTE_SIGNER_TIMEOUT)) as session:
            response = await session.post(signer_url, json=dataclasses.asdict(data))

            if response.status == 404:
                # Pubkey not present on remote signer side
                raise RuntimeError(
                    f'Failed to get signature for {public_key.hex()}.'
                    f' Is this public key present in the remote signer?'
                )

            response.raise_for_status()

            signature = (await response.json())['signature']
        return BLSSignature(Web3.to_bytes(hexstr=signature))

    @staticmethod
    async def _sign_deposit_data_request(
        public_key: HexStr,
        amount: int,
        withdrawal_credentials: bytes,
        signing_root: bytes,
        fork_version: bytes,
    ) -> BLSSignature:
        data = DepositRequestModel(
            deposit=DepositMessage(
                pubkey=public_key,
                amount=str(amount),
                withdrawal_credentials=HexStr(withdrawal_credentials.hex()),
                fork_version=HexStr(fork_version.hex()),
            ),
            signing_root=HexStr(signing_root.hex()),
            type='DEPOSIT',
        )

        signer_base_url = cast(str, settings.remote_signer_url)
        signer_url = urljoin(signer_base_url, f'/api/v1/eth2/sign/0x{public_key}')

        async with ClientSession(timeout=ClientTimeout(REMOTE_SIGNER_TIMEOUT)) as session:
            response = await session.post(signer_url, json=dataclasses.asdict(data))

            if response.status == 404:
                # Pubkey not present on remote signer side
                raise RuntimeError(
                    f'Failed to sign deposit data for {public_key}.'
                    f' Is this public key present in the remote signer?'
                )

            response.raise_for_status()

            signature = (await response.json())['signature']
        return BLSSignature(Web3.to_bytes(hexstr=signature))

    def _get_deposit_signing_root(
        self, public_key: BLSPubkey, amount: int, withdrawal_credentials: bytes, fork_version: bytes
    ) -> bytes:
        deposit_message = SerializableDepositMessage(
            pubkey=public_key,
            withdrawal_credentials=withdrawal_credentials,
            amount=amount,
        )
        domain = compute_deposit_domain(fork_version)
        return compute_signing_root(deposit_message, domain)
