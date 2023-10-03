import asyncio
from dataclasses import dataclass
from pathlib import Path

import click
import milagro_bls_binding as bls
from aiohttp import ClientResponseError
from eth_typing import BLSPubkey, BLSSignature, HexAddress, HexStr
from sw_utils import ValidatorStatus
from sw_utils.consensus import EXITED_STATUSES
from sw_utils.signing import get_exit_message_signing_root
from sw_utils.typings import ConsensusFork
from web3 import Web3

from src.common.clients import consensus_client
from src.common.utils import log_verbose
from src.common.validators import validate_eth_address
from src.common.vault_config import VaultConfig
from src.config.settings import AVAILABLE_NETWORKS, NETWORKS, settings
from src.validators.signing.hashi_vault import (
    HashiVaultConfiguration,
    load_hashi_vault_keys,
)
from src.validators.signing.key_shares import reconstruct_shared_bls_signature
from src.validators.signing.remote import RemoteSignerConfiguration, get_signature_shard
from src.validators.typings import BLSPrivkey, Keystores
from src.validators.utils import load_keystores


@dataclass
class ExitKeystore:
    private_key: BLSPrivkey | None
    public_key: HexStr
    index: int


EXITING_STATUSES = [ValidatorStatus.ACTIVE_EXITING] + EXITED_STATUSES


@click.option(
    '--network',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
    envvar='NETWORK',
    help='The network of the vault. Default is the network specified at "init" command.',
)
@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the vault data is placed. Default is ~/.stakewise.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    '--vault',
    prompt='Enter your vault address',
    help='Vault address',
    type=str,
    callback=validate_eth_address,
)
@click.option(
    '--count',
    help='The number of validators to exit.',
    type=click.IntRange(min=1),
)
@click.option(
    '--consensus-endpoints',
    help='Comma separated list of API endpoints for consensus nodes',
    prompt='Enter the comma separated list of API endpoints for consensus nodes',
    envvar='CONSENSUS_ENDPOINTS',
    type=str,
)
@click.option(
    '--remote-signer-url',
    type=str,
    envvar='REMOTE_SIGNER_URL',
    help='The base URL of the remote signer, e.g. http://signer:9000',
)
@click.option(
    '--hashi-vault-url',
    envvar='HASHI_VAULT_URL',
    help='The base URL of the vault service, e.g. http://vault:8200.',
)
@click.option(
    '--hashi-vault-token',
    envvar='HASHI_VAULT_TOKEN',
    help='Authentication token for accessing Hashi vault.',
)
@click.option(
    '--hashi-vault-key-path',
    envvar='HASHI_VAULT_KEY_PATH',
    help='Key path in the K/V secret engine where validator signing keys are stored.',
)
@click.option(
    '-v',
    '--verbose',
    help='Enable debug mode. Default is false.',
    envvar='VERBOSE',
    is_flag=True,
)
@click.command(help='Performs a voluntary exit for active vault validators.')
# pylint: disable-next=too-many-arguments
def validators_exit(
    network: str,
    vault: HexAddress,
    count: int | None,
    consensus_endpoints: str,
    remote_signer_url: str,
    hashi_vault_key_path: str | None,
    hashi_vault_token: str | None,
    hashi_vault_url: str | None,
    data_dir: str,
    verbose: bool,
) -> None:
    # pylint: disable=duplicate-code
    vault_config = VaultConfig(vault, Path(data_dir))
    if network is None:
        vault_config.load()
        network = vault_config.network

    settings.set(
        vault=vault,
        network=network,
        vault_dir=vault_config.vault_dir,
        consensus_endpoints=consensus_endpoints,
        remote_signer_url=remote_signer_url,
        hashi_vault_token=hashi_vault_token,
        hashi_vault_key_path=hashi_vault_key_path,
        hashi_vault_url=hashi_vault_url,
        verbose=verbose,
    )
    try:
        asyncio.run(main(count))
    except Exception as e:
        log_verbose(e)


async def main(count: int | None) -> None:
    keystores = load_keystores()
    remote_signer_config = None
    fork = await consensus_client.get_consensus_fork()

    if len(keystores) > 0:
        all_validator_pubkeys = list(keystores.keys())  # pylint: disable=no-member
    else:
        if settings.hashi_vault_url:
            # No keystores loaded but hashi vault configuration specified
            hashi_vault_config = HashiVaultConfiguration.from_settings()
            click.echo('Using hashi vault at %s for loading public keys')
            keystores = await load_hashi_vault_keys(hashi_vault_config)
            all_validator_pubkeys = list(keystores.keys())

        elif settings.remote_signer_url:
            # No keystores loaded but remote signer URL provided
            remote_signer_config = RemoteSignerConfiguration.from_file(
                settings.remote_signer_config_file
            )
            all_validator_pubkeys = list(remote_signer_config.pubkeys_to_shares.keys())
            click.echo(
                f'Using remote signer at {settings.remote_signer_url}'
                f' for {len(all_validator_pubkeys)} public keys',
            )
        else:
            raise RuntimeError('No keystores, no remote signer or hashi vault URL provided')

    exit_keystores = await _get_exit_keystores(
        keystores=keystores, public_keys=all_validator_pubkeys
    )
    if not exit_keystores:
        raise click.ClickException('There are no active validators.')

    exit_keystores.sort(key=lambda x: x.index)

    if count:
        exit_keystores = exit_keystores[:count]

    click.confirm(
        f'Are you sure you want to exit {len(exit_keystores)} validators '
        f'with indexes: {", ".join(str(x.index) for x in exit_keystores)}?',
        abort=True,
    )
    exited_indexes = []
    for exit_keystore in exit_keystores:
        exit_signature = await _get_exit_signature(
            exit_keystore=exit_keystore,
            remote_signer_config=remote_signer_config,
            fork=fork,
            network=settings.network,
        )
        try:
            await consensus_client.submit_voluntary_exit(
                validator_index=exit_keystore.index,
                signature=Web3.to_hex(exit_signature),
                epoch=fork.epoch,
            )
        except ClientResponseError as e:
            # Validator status is updated in CL after some delay.
            # Status may be active in CL although validator has started exit process.
            # CL will return status 400 for exit request in this case.
            log_verbose(e)
            continue

        exited_indexes.append(exit_keystore.index)

    if exited_indexes:
        click.secho(
            f'Validators {", ".join(str(index) for index in exited_indexes)} '
            f'({len(exited_indexes)} of {len(exit_keystores)}) '
            f'exits successfully initiated',
            bold=True,
            fg='green',
        )


async def _get_exit_signature(
    exit_keystore: ExitKeystore,
    remote_signer_config: RemoteSignerConfiguration | None,
    fork: ConsensusFork,
    network: str,
) -> BLSSignature:
    """Generates exit signature"""
    message = get_exit_message_signing_root(
        validator_index=exit_keystore.index,
        genesis_validators_root=NETWORKS[network].GENESIS_VALIDATORS_ROOT,
        fork=fork,
    )
    if exit_keystore.private_key:
        exit_signature = bls.Sign(exit_keystore.private_key, message)
    elif remote_signer_config:
        # Use remote signer
        signature_shards = []
        for pubkey_share in remote_signer_config.pubkeys_to_shares[exit_keystore.public_key]:
            signature_shards.append(
                await get_signature_shard(
                    pubkey_share=BLSPubkey(Web3.to_bytes(hexstr=pubkey_share)),
                    validator_index=exit_keystore.index,
                    fork=fork,
                    message=message,
                )
            )
        exit_signature = reconstruct_shared_bls_signature(
            signatures=dict(enumerate(signature_shards))
        )
        bls.Verify(
            BLSPubkey(Web3.to_bytes(hexstr=exit_keystore.public_key)), message, exit_signature
        )
    else:
        raise RuntimeError(
            'Unable to sign exit message - no private key/remote signer configuration'
        )
    return exit_signature


async def _get_exit_keystores(
    keystores: Keystores, public_keys: list[HexStr]
) -> list[ExitKeystore]:
    """Fetches validators consensus info."""
    results = []
    exited_statuses = [x.value for x in EXITING_STATUSES]

    for i in range(0, len(public_keys), settings.validators_fetch_chunk_size):
        validators = await consensus_client.get_validators_by_ids(
            public_keys[i : i + settings.validators_fetch_chunk_size]
        )
        for beacon_validator in validators['data']:
            if beacon_validator.get('status') in exited_statuses:
                continue

            results.append(
                ExitKeystore(
                    public_key=beacon_validator['validator']['pubkey'],
                    private_key=keystores[beacon_validator['validator']['pubkey']]
                    if len(keystores) > 0
                    else None,
                    index=int(beacon_validator['index']),
                )
            )
    return results
