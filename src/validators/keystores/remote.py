import dataclasses
import json
import logging
from dataclasses import dataclass
from pathlib import Path

import milagro_bls_binding as bls
from aiohttp import ClientSession, ClientTimeout
from eth_typing import BLSPubkey, BLSSignature, HexStr
from sw_utils import get_exit_message_signing_root
from sw_utils.typings import ConsensusFork, ProtocolConfig
from web3 import Web3

from src.config.settings import NETWORKS, REMOTE_SIGNER_TIMEOUT, settings
from src.validators.keystores.base import BaseKeystore
from src.validators.signing.common import encrypt_signature
from src.validators.signing.key_shares import reconstruct_shared_bls_signature
from src.validators.typings import ExitSignatureShards

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
    pubkeys_to_shares: dict[HexStr, list[HexStr]]

    def __init__(self, pubkeys_to_shares: dict[HexStr, list[HexStr]]):
        self.pubkeys_to_shares = pubkeys_to_shares

    def __bool__(self) -> bool:
        return len(self.pubkeys_to_shares) > 0

    def __len__(self) -> int:
        return len(self.pubkeys_to_shares)

    def __contains__(self, public_key):
        return public_key in self.pubkeys_to_shares

    @classmethod
    def load_from_data(cls, data: dict) -> 'RemoteSignerKeystore':
        return cls._load_data(data)

    @classmethod
    def load_from_file(cls, path: str | Path) -> 'RemoteSignerKeystore':
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls._load_data(data['pubkeys_to_shares'])

    @classmethod
    async def load(cls) -> 'RemoteSignerKeystore':
        return cls.load_from_file(settings.remote_signer_config_file)

    def save(self, path: str | Path) -> None:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({'pubkeys_to_shares': self.pubkeys_to_shares}, f)

    async def get_exit_signature_shards(
        self,
        validator_index: int,
        public_key: HexStr,
        protocol_config: ProtocolConfig,
        fork: ConsensusFork,
    ) -> ExitSignatureShards:
        oracle_public_keys = [oracle.public_key for oracle in protocol_config.oracles]
        message = get_exit_message_signing_root(
            validator_index=validator_index,
            genesis_validators_root=settings.network_config.GENESIS_VALIDATORS_ROOT,
            fork=fork,
        )
        pubkey_shares = self.pubkeys_to_shares.get(public_key)
        if not pubkey_shares:
            raise RuntimeError(f'Failed to get signature for {public_key}.')

        validator_pubkey_shares = [BLSPubkey(Web3.to_bytes(hexstr=s)) for s in pubkey_shares]

        signature_shards = []
        for validator_pubkey_share, oracle_pubkey in zip(
            validator_pubkey_shares, oracle_public_keys
        ):
            shard = await self._fetch_signature_shard(
                pubkey_share=validator_pubkey_share,
                validator_index=validator_index,
                fork=fork,
                message=message,
            )

            # Encrypt it with the oracle's pubkey
            signature_shards.append(encrypt_signature(oracle_pubkey, shard))

        return ExitSignatureShards(
            public_keys=[Web3.to_hex(pubkey) for pubkey in validator_pubkey_shares],
            exit_signatures=signature_shards,
        )

    async def get_exit_signature(
        self, validator_index: int, public_key: HexStr, network: str, fork: ConsensusFork
    ) -> BLSSignature:
        message = get_exit_message_signing_root(
            validator_index=validator_index,
            genesis_validators_root=NETWORKS[network].GENESIS_VALIDATORS_ROOT,
            fork=fork,
        )
        signature_shards = []
        for pubkey_share in self.pubkeys_to_shares[public_key]:
            signature_shards.append(
                await self._fetch_signature_shard(
                    pubkey_share=BLSPubkey(Web3.to_bytes(hexstr=pubkey_share)),
                    validator_index=validator_index,
                    fork=fork,
                    message=message,
                )
            )
        exit_signature = reconstruct_shared_bls_signature(
            signatures=dict(enumerate(signature_shards))
        )
        bls.Verify(BLSPubkey(Web3.to_bytes(hexstr=public_key)), message, exit_signature)
        return exit_signature

    @property
    def public_keys(self) -> list[HexStr]:
        return list(self.pubkeys_to_shares.keys())

    @classmethod
    def _load_data(cls, data: dict) -> 'RemoteSignerKeystore':
        pubkeys_to_shares = {}
        for full_pubkey, pubkey_shares in data.items():
            pubkeys_to_shares[full_pubkey] = [HexStr(s) for s in pubkey_shares]

        if len(pubkeys_to_shares.keys()) == 0:
            raise RuntimeError('Remote signer config does not contain any pubkeys')

        return RemoteSignerKeystore(pubkeys_to_shares=pubkeys_to_shares)

    async def _fetch_signature_shard(
        self,
        pubkey_share: BLSPubkey,
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
            signer_url = f'{settings.remote_signer_url}/api/v1/eth2/sign/0x{pubkey_share.hex()}'

            response = await session.post(signer_url, json=dataclasses.asdict(data))

            if response.status == 404:
                # Pubkey not present on remote signer side
                raise RuntimeError(
                    f'Failed to get signature for {pubkey_share.hex()}.'
                    f' Is this keyshare present in the remote signer?'
                    f' If the oracle set changed, you may need to regenerate'
                    f' and reimport the new key shares!'
                )

            response.raise_for_status()

            signature = (await response.json())['signature']
            return BLSSignature(Web3.to_bytes(hexstr=signature))
