import asyncio
import os
from pathlib import Path

import click
from click import Context
from eth_typing import ChecksumAddress, HexAddress

from src.common.utils import greenify, log_verbose
from src.common.validators import validate_db_uri, validate_eth_address
from src.common.vault_config import VaultConfig
from src.config.settings import AVAILABLE_NETWORKS, settings
from src.remote_db import tasks
from src.remote_db.database import check_db_connection


@click.group('remote-db', help='Manages Postgres database encrypted keystores.')
@click.option(
    '--vault',
    prompt='Enter your vault address',
    help='The vault address',
    type=str,
    callback=validate_eth_address,
)
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
    '--db-url',
    help='The endpoint for the Postgres DB connection. '
    'For example, postgresql://username:pass@hostname/dbname.',
    required=True,
    prompt='Enter the Postgres DB connection URL (e.g. postgresql://username:pass@hostname/dbname)',
    callback=validate_db_uri,
)
@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the vault data will be placed. Default is ~/.stakewise.',
    type=click.Path(file_okay=False, dir_okay=True),
)
@click.option(
    '--keystores-dir',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    envvar='KEYSTORES_DIR',
    help='Absolute path to the directory with all the encrypted keystores. '
    'Default is the directory generated with "create-keys" command.',
    required=False,
)
@click.option(
    '-v',
    '--verbose',
    help='Enable debug mode. Default is false.',
    envvar='VERBOSE',
    is_flag=True,
)
@click.pass_context
# pylint: disable-next=too-many-arguments,too-many-locals
def remote_db_group(
    ctx: Context,
    vault: HexAddress,
    data_dir: str,
    keystores_dir: str | None,
    db_url: str,
    network: str | None,
    verbose: bool,
) -> None:
    ctx.ensure_object(dict)

    config = VaultConfig(vault, Path(data_dir))
    if network is None:
        config.load()
        network = config.network

    settings.set(
        vault=vault,
        vault_dir=config.vault_dir,
        network=network,
        keystores_dir=keystores_dir,
        verbose=verbose,
    )

    check_db_connection(db_url)
    ctx.obj['db_url'] = db_url


@remote_db_group.command(help='Creates database tables and generates new encryption key.')
@click.pass_context
def setup(ctx: Context) -> None:
    encryption_key = tasks.setup(ctx.obj['db_url'])
    click.echo(
        f'Successfully configured remote database.\n'
        f'Encryption key: {greenify(encryption_key)}\n'
        f'{click.style("NB! You must store your encryption in a secure cold storage!", bold=True)}'
    )


@remote_db_group.command(help='Removes all the entries for the vault from the database.')
@click.pass_context
def cleanup(ctx: Context) -> None:
    tasks.cleanup(ctx.obj['db_url'])
    click.echo(f'Successfully removed all the entries for the {greenify(settings.vault)} vault.')


@remote_db_group.command(
    help='Generates shares for the local keypairs, updates configs in the remote DB.'
)
@click.option(
    '--encrypt-key',
    envvar='REMOTE_DB_ENCRYPT_KEY',
    help='The encryption key for the remote database.',
    required=True,
    prompt='Enter the encryption key for the remote database',
)
@click.option(
    '--execution-endpoints',
    type=str,
    envvar='EXECUTION_ENDPOINTS',
    prompt='Enter comma separated list of API endpoints for execution nodes',
    help='Comma separated list of API endpoints for execution nodes.',
)
@click.option(
    '--deposit-data-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    envvar='DEPOSIT_DATA_FILE',
    help='Path to the deposit_data.json file. '
    'Default is the file generated with "create-keys" command.',
)
@click.pass_context
def upload_keypairs(
    ctx: Context,
    encrypt_key: str,
    execution_endpoints: str,
    deposit_data_file: str | None,
) -> None:
    settings.set(
        vault=settings.vault,
        vault_dir=settings.vault_dir,
        network=settings.network,
        keystores_dir=str(settings.keystores_dir),
        deposit_data_file=deposit_data_file,
        verbose=settings.verbose,
        execution_endpoints=execution_endpoints,
    )
    try:
        asyncio.run(tasks.upload_keypairs(ctx.obj['db_url'], encrypt_key))
        click.echo(
            f'Successfully uploaded keypairs and shares for the {greenify(settings.vault)} vault.'
        )
    except Exception as e:
        log_verbose(e)


@remote_db_group.command(help='Retrieves web3signer private keys from the database.')
@click.option(
    '--encrypt-key',
    envvar='REMOTE_DB_ENCRYPT_KEY',
    help='The encryption key for the remote database.',
    required=True,
    prompt='Enter the encryption key for the remote database',
)
@click.option(
    '--output-dir',
    envvar='REMOTE_DB_OUTPUT_DIR',
    help='The folder where web3signer keystores will be saved.',
    prompt='Enter the folder where web3signer keystores will be saved',
    default=os.getcwd(),
    type=click.Path(exists=False, file_okay=False, dir_okay=True),
)
@click.pass_context
def setup_web3signer(ctx: Context, encrypt_key: str, output_dir: str) -> None:
    tasks.setup_web3signer(ctx.obj['db_url'], encrypt_key, Path(output_dir))
    click.echo('Successfully retrieved web3signer private keys from the database.')


@remote_db_group.command(
    help='Creates validator configuration files for Lighthouse, '
    'Prysm, and Teku clients to sign data using keys from database.'
)
@click.option(
    '--validator-index',
    help='The validator index to generate the configuration files.',
    prompt='Enter the validator index to generate the configuration files',
    type=click.IntRange(min=0),
)
@click.option(
    '--total-validators',
    help='The total number of validators connected to the web3signer.',
    prompt='Enter the total number of validators connected to the web3signer',
    type=click.IntRange(min=1),
)
@click.option(
    '--web3signer-endpoint',
    help='The endpoint of the web3signer service.',
    prompt='Enter the endpoint of the web3signer service',
)
@click.option(
    '--fee-recipient',
    help='The recipient address for MEV & priority fees.',
    prompt='Enter the recipient address for MEV & priority fees',
    callback=validate_eth_address,
)
@click.option(
    '--disable-proposal-builder',
    is_flag=True,
    default=False,
    help='Disable proposal builder for Teku and Prysm clients.',
)
@click.option(
    '--output-dir',
    envvar='REMOTE_DB_OUTPUT_DIR',
    help='The folder where configuration files will be saved.',
    prompt='Enter the folder where configuration files will be saved',
    default=os.getcwd(),
    type=click.Path(exists=False, file_okay=False, dir_okay=True),
)
@click.pass_context
# pylint: disable-next=too-many-arguments
def setup_validator(
    ctx: Context,
    validator_index: int,
    total_validators: int,
    web3signer_endpoint: str,
    fee_recipient: ChecksumAddress,
    disable_proposal_builder: bool,
    output_dir: str,
) -> None:
    if total_validators <= validator_index:
        raise click.BadParameter('validator index must be less than total validators')

    tasks.setup_validator(
        db_url=ctx.obj['db_url'],
        validator_index=validator_index,
        total_validators=total_validators,
        web3signer_endpoint=web3signer_endpoint,
        fee_recipient=fee_recipient,
        disable_proposal_builder=disable_proposal_builder,
        output_dir=Path(output_dir),
    )
    click.echo('Successfully created validator configuration files.')


@remote_db_group.command(help='Create operator remote signer configuration.')
@click.option(
    '--output-dir',
    envvar='REMOTE_DB_OUTPUT_DIR',
    help='The folder where configuration file will be saved.',
    required=False,
    type=click.Path(exists=False, file_okay=False, dir_okay=True),
)
@click.pass_context
def setup_operator(ctx: Context, output_dir: str | None) -> None:
    dest_dir = Path(output_dir) if output_dir is not None else settings.vault_dir
    tasks.setup_operator(
        db_url=ctx.obj['db_url'],
        output_dir=dest_dir,
    )
    click.echo('Successfully created operator configuration file.')
