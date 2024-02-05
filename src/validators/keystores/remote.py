import dataclasses
import logging
from dataclasses import dataclass

import milagro_bls_binding as bls
from aiohttp import ClientSession, ClientTimeout
from eth_typing import BLSPubkey, BLSSignature, HexStr
from sw_utils import get_exit_message_signing_root
from sw_utils.typings import ConsensusFork
from web3 import Web3

from src.common.typings import Oracles
from src.config.networks import NETWORKS
from src.config.settings import REMOTE_SIGNER_TIMEOUT, settings
from src.validators.keystores.base import BaseKeystore
from src.validators.signing.common import encrypt_signature
from src.validators.signing.key_shares import bls_signature_and_public_key_to_shares
from src.validators.typings import ExitSignatureShards
from src.validators.utils import load_deposit_data

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


class RemoteSignerKeystore(BaseKeystore):
    def __init__(self, public_keys: list[HexStr]):
        self._public_keys = public_keys

    @staticmethod
    async def load() -> 'BaseKeystore':
        deposit_data = load_deposit_data(settings.vault, settings.deposit_data_file)
        return RemoteSignerKeystore(deposit_data.public_keys)

    def __bool__(self) -> bool:
        return bool(self._public_keys)

    def __len__(self) -> int:
        return len(self._public_keys)

    def __contains__(self, public_key):
        return public_key in self._public_keys

    @property
    def public_keys(self) -> list[HexStr]:
        return self._public_keys

    async def get_exit_signature_shards(
        self,
        validator_index: int,
        public_key: HexStr,
        oracles: Oracles,
        fork: ConsensusFork,
    ) -> ExitSignatureShards:
        message = get_exit_message_signing_root(
            validator_index=validator_index,
            genesis_validators_root=settings.network_config.GENESIS_VALIDATORS_ROOT,
            fork=fork,
        )

        public_key_bytes = BLSPubkey(Web3.to_bytes(hexstr=public_key))
        threshold = oracles.exit_signature_recover_threshold
        total = len(oracles.public_keys)

        exit_signature = await self._sign(public_key_bytes, validator_index, fork, message)

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
        message = get_exit_message_signing_root(
            validator_index=validator_index,
            genesis_validators_root=NETWORKS[network].GENESIS_VALIDATORS_ROOT,
            fork=fork,
        )
        public_key_bytes = BLSPubkey(Web3.to_bytes(hexstr=public_key))

        exit_signature = await self._sign(public_key_bytes, validator_index, fork, message)

        bls.Verify(BLSPubkey(Web3.to_bytes(hexstr=public_key)), message, exit_signature)
        return exit_signature

    async def _sign(
        self,
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

        async with ClientSession(timeout=ClientTimeout(REMOTE_SIGNER_TIMEOUT)) as session:
            signer_url = f'{settings.remote_signer_url}/api/v1/eth2/sign/0x{public_key.hex()}'

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
