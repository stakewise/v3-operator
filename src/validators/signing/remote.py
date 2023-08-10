import dataclasses
import json
from dataclasses import dataclass
from pathlib import Path

from aiohttp import ClientSession, ClientTimeout
from eth_typing import BLSPubkey, BLSSignature, HexStr
from sw_utils import get_exit_message_signing_root
from sw_utils.typings import ConsensusFork
from web3 import Web3

from src.common.typings import Oracles
from src.config.settings import REMOTE_SIGNER_TIMEOUT, settings
from src.validators.signing.common import encrypt_signature
from src.validators.typings import ExitSignatureShards


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
    # Camel case for this parameter only as per the docs
    signingRoot: HexStr
    type: str
    voluntary_exit: VoluntaryExitMessage


@dataclass
class RemoteSignerConfiguration:
    pubkeys_to_shares: dict[HexStr, list[HexStr]]

    def save(self, path: str | Path) -> None:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(dataclasses.asdict(self), f)

    @classmethod
    def from_file(cls, path: str | Path) -> 'RemoteSignerConfiguration':
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            pubkeys_to_shares = {}
            for full_pubkey, pubkey_shares in data['pubkeys_to_shares'].items():
                pubkeys_to_shares[full_pubkey] = [HexStr(s) for s in pubkey_shares]

            if len(pubkeys_to_shares.keys()) == 0:
                raise RuntimeError('Remote signer config does not contain any pubkeys')

            return cls(pubkeys_to_shares=pubkeys_to_shares)


async def get_signature_shard(
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
            genesis_validators_root=HexStr(settings.network_config.GENESIS_VALIDATORS_ROOT.hex()),
        ),
        signingRoot=HexStr(message.hex()),
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


async def get_exit_signature_shards_remote_signer(
    validator_index: int,
    validator_pubkey_shares: list[BLSPubkey],
    oracles: Oracles,
    fork: ConsensusFork,
) -> ExitSignatureShards:
    message = get_exit_message_signing_root(
        validator_index=validator_index,
        genesis_validators_root=settings.network_config.GENESIS_VALIDATORS_ROOT,
        fork=fork,
    )

    signature_shards = []
    for validator_pubkey_share, oracle_pubkey in zip(validator_pubkey_shares, oracles.public_keys):
        shard = await get_signature_shard(
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
