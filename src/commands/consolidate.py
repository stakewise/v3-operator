import asyncio
import logging
import sys
from pathlib import Path

import click
from eth_typing import BlockNumber, ChecksumAddress, HexStr
from eth_utils import add_0x_prefix
from sw_utils import ChainHead
from web3 import Web3
from web3.types import Gwei, Wei

from src.common.clients import close_clients, setup_clients
from src.common.consensus import get_chain_latest_head
from src.common.consolidations import (
    get_consolidation_request_fee,
    get_consolidations_count,
)
from src.common.contracts import VaultContract
from src.common.execution import check_gas_price
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.protocol_config import get_protocol_config
from src.common.utils import log_verbose
from src.common.validators import (
    validate_eth_address,
    validate_max_validator_balance_gwei,
    validate_public_key,
    validate_public_keys,
    validate_public_keys_file,
)
from src.common.wallet import wallet
from src.config.config import OperatorConfig
from src.config.networks import AVAILABLE_NETWORKS, GNOSIS, MAINNET, NETWORKS
from src.config.settings import DEFAULT_MAX_CONSOLIDATION_REQUEST_FEE_GWEI, settings
from src.validators.consolidation_manager import ConsolidationManager
from src.validators.exceptions import ConsolidationError
from src.validators.oracles import poll_consolidation_signature
from src.validators.register_validators import submit_consolidate_validators
from src.validators.relayer import RelayerClient
from src.validators.typings import ConsolidationKeys

logger = logging.getLogger(__name__)


@click.option(
    '--data-dir',
    default=str(Path.home() / '.stakewise'),
    envvar='DATA_DIR',
    help='Path where the config data is placed. Default is ~/.stakewise.',
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    '--network',
    help='The network of the vault. Default is the network specified at "init" command.',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
)
@click.option(
    '--vault',
    prompt='Enter your vault address',
    help='Vault address',
    type=str,
    callback=validate_eth_address,
)
@click.option(
    '--source-public-keys',
    type=HexStr,
    callback=validate_public_keys,
    help='Comma separated list of public keys of validators to consolidate from.',
)
@click.option(
    '--source-public-keys-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    callback=validate_public_keys_file,
    help='File with public keys of validators to consolidate from.',
)
@click.option(
    '--target-public-key',
    type=HexStr,
    callback=validate_public_key,
    help='Public key of validator to consolidate to.',
)
@click.option(
    '--exclude-public-keys-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    callback=validate_public_keys_file,
    help='File with public keys of validators to exclude from consolidation.',
)
@click.option(
    '--consensus-endpoints',
    help='Comma separated list of API endpoints for consensus nodes',
    prompt='Enter the comma separated list of API endpoints for consensus nodes',
    envvar='CONSENSUS_ENDPOINTS',
    type=str,
)
@click.option(
    '--execution-endpoints',
    type=str,
    envvar='EXECUTION_ENDPOINTS',
    prompt='Enter the comma separated list of API endpoints for execution nodes',
    help='Comma separated list of API endpoints for execution nodes.',
)
@click.option(
    '--wallet-password-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    envvar='WALLET_PASSWORD_FILE',
    help='Absolute path to the wallet password file. '
    'Default is the file generated with "create-wallet" command.',
)
@click.option(
    '--wallet-file',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    envvar='WALLET_FILE',
    help='Absolute path to the wallet. '
    'Default is the file generated with "create-wallet" command.',
)
@click.option(
    '--relayer-endpoint',
    type=str,
    help='Relayer endpoint.',
    envvar='RELAYER_ENDPOINT',
)
@click.option(
    '--max-validator-balance-gwei',
    type=int,
    envvar='MAX_VALIDATOR_BALANCE_GWEI',
    help=f'The maximum validator balance in Gwei.'
    f'Default is {NETWORKS[MAINNET].MAX_VALIDATOR_BALANCE_GWEI} Gwei for Ethereum, '
    f'{NETWORKS[GNOSIS].MAX_VALIDATOR_BALANCE_GWEI} Gwei for Gnosis.',
    callback=validate_max_validator_balance_gwei,
)
@click.option(
    '--max-consolidation-request-fee-gwei',
    type=int,
    envvar='MAX_CONSOLIDATION_REQUEST_FEE_GWEI',
    help='The maximum consolidation request fee in Gwei. ',
    default=DEFAULT_MAX_CONSOLIDATION_REQUEST_FEE_GWEI,
    show_default=True,
)
@click.option(
    '-v',
    '--verbose',
    help='Enable debug mode. Default is false.',
    envvar='VERBOSE',
    is_flag=True,
)
@click.option(
    '--no-switch-consolidation',
    is_flag=True,
    help='Disables switching a 0x01 validator to 0x02 when no public keys are provided.'
    ' Default is false.',
)
@click.option(
    '--no-confirm',
    is_flag=True,
    help='Skips confirmation messages when provided. Default is false.',
)
@click.option(
    '--log-level',
    type=click.Choice(
        LOG_LEVELS,
        case_sensitive=False,
    ),
    default='INFO',
    envvar='LOG_LEVEL',
    help='The log level.',
)
@click.option(
    '--vault-first-block',
    type=int,
    envvar='VAULT_FIRST_BLOCK',
    help='The block number where the vault was created. Used to optimize fetching vault events.',
)
@click.command(
    help='Performs a vault validators consolidation from 0x01 validators to 0x02 validator. '
    'Switches a validator from 0x01 to 0x02 if the source and target keys are identical.'
)
# pylint: disable-next=too-many-arguments,too-many-locals
def consolidate(
    vault: ChecksumAddress,
    execution_endpoints: str,
    consensus_endpoints: str,
    data_dir: str,
    wallet_file: str | None,
    wallet_password_file: str | None,
    network: str | None,
    verbose: bool,
    no_switch_consolidation: bool,
    no_confirm: bool,
    log_level: str,
    max_consolidation_request_fee_gwei: int,
    source_public_keys: list[HexStr] | None,
    source_public_keys_file: Path | None,
    target_public_key: HexStr | None,
    exclude_public_keys_file: Path | None,
    relayer_endpoint: str | None,
    max_validator_balance_gwei: int | None,
    vault_first_block: BlockNumber | None,
) -> None:
    if all([source_public_keys, source_public_keys_file]):
        raise click.ClickException(
            'Provide only one parameter: either --source-public-keys-file or --source-public-keys.'
        )
    if not (source_public_keys or source_public_keys_file) and target_public_key:
        raise click.ClickException(
            'One of these parameters must be provided with target-public-key:'
            ' --source-public-keys-file or --source-public-keys.'
        )
    if (source_public_keys or source_public_keys_file) and not target_public_key:
        raise click.ClickException(
            '--target-public-key must be provided when using'
            ' --source-public-keys-file or --source-public-keys.'
        )

    if source_public_keys_file:
        source_public_keys = _load_public_keys(source_public_keys_file)

    exclude_public_keys: set[HexStr] = set()

    if exclude_public_keys_file:
        exclude_public_keys = set(_load_public_keys(exclude_public_keys_file))

    if source_public_keys and exclude_public_keys:
        raise click.ClickException(
            '--exclude-public-keys and --source-public-keys are mutually exclusive.'
        )

    operator_config = OperatorConfig(vault, Path(data_dir))

    if network is None and not operator_config.exists:
        raise click.ClickException(
            'Either provide the network using --network option or run "init" command first.'
        )

    if network is None:
        operator_config.load()
        network = operator_config.network

    settings.set(
        vault=vault,
        network=network,
        vault_dir=operator_config.vault_dir,
        execution_endpoints=execution_endpoints,
        consensus_endpoints=consensus_endpoints,
        wallet_file=wallet_file,
        wallet_password_file=wallet_password_file,
        relayer_endpoint=relayer_endpoint,
        max_validator_balance_gwei=(
            Gwei(max_validator_balance_gwei) if max_validator_balance_gwei else None
        ),
        verbose=verbose,
        log_level=log_level,
        vault_first_block=vault_first_block,
    )
    try:
        asyncio.run(
            main(
                source_public_keys=source_public_keys,
                target_public_key=target_public_key,
                exclude_public_keys=exclude_public_keys,
                no_switch_consolidation=no_switch_consolidation,
                max_consolidation_request_fee_gwei=Gwei(max_consolidation_request_fee_gwei),
                no_confirm=no_confirm,
            )
        )
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


# pylint: disable-next=too-many-arguments
async def main(
    source_public_keys: list[HexStr] | None,
    target_public_key: HexStr | None,
    exclude_public_keys: set[HexStr],
    no_switch_consolidation: bool,
    max_consolidation_request_fee_gwei: Gwei,
    no_confirm: bool,
) -> None:
    setup_logging()
    await setup_clients()
    try:
        await process(
            source_public_keys=source_public_keys,
            target_public_key=target_public_key,
            exclude_public_keys=exclude_public_keys,
            no_switch_consolidation=no_switch_consolidation,
            max_consolidation_request_fee_gwei=Gwei(max_consolidation_request_fee_gwei),
            no_confirm=no_confirm,
        )
    finally:
        await close_clients()


# pylint: disable-next=too-many-locals,too-many-arguments
async def process(
    source_public_keys: list[HexStr] | None,
    target_public_key: HexStr | None,
    exclude_public_keys: set[HexStr],
    no_switch_consolidation: bool,
    max_consolidation_request_fee_gwei: Gwei,
    no_confirm: bool,
) -> None:
    # pylint: disable=line-too-long
    """
    Consolidate validators from source public keys to target public key.
    First validate the consolidation request is correct and consensus can handle it.
    Check validation details: https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/beacon-chain.md#new-process_consolidation_request
    Then send the request to the contract.
    """
    chain_head = await get_chain_latest_head()

    await _check_validators_manager()
    await _check_consolidations_queue(chain_head)

    consolidation_keys = None
    if source_public_keys and target_public_key:
        consolidation_keys = ConsolidationKeys(
            source_public_keys=source_public_keys,
            target_public_key=target_public_key,
        )
    consolidation_manager = await ConsolidationManager.create(
        consolidation_keys=consolidation_keys,
        chain_head=chain_head,
        exclude_public_keys=exclude_public_keys,
    )
    try:
        target_source = consolidation_manager.get_target_source()
    except ConsolidationError as e:
        raise click.ClickException(str(e))
    if not target_source:
        raise click.ClickException(f'Validators in vault {settings.vault} can\'t be consolidated')

    for target_validator, source_validator in target_source:
        if source_validator.index == target_validator.index:
            if no_switch_consolidation:
                raise click.ClickException(
                    f'Validator with index {source_validator.index} can\'t be consolidated as switching is disabled.'
                )
            click.secho(
                f'Switching validator with index {source_validator.index} to compounding',
            )
        else:
            click.secho(
                f'Consolidating from validator with index {source_validator.index} '
                f'to validator with index {target_validator.index}'
            )
    if not no_confirm:
        click.confirm(
            'Proceed consolidation?',
            default=True,
            abort=True,
        )

    if not await check_gas_price():
        return

    protocol_config = await get_protocol_config()

    target_source_public_keys = [
        (target_validator.public_key, source_validator.public_key)
        for target_validator, source_validator in target_source
    ]
    consolidations_count = len(target_source_public_keys)

    consolidation_request_fee = await get_consolidation_request_fee(count=consolidations_count)
    if consolidation_request_fee > Web3.to_wei(max_consolidation_request_fee_gwei, 'gwei'):
        logger.info(
            'The current consolidation fee per one consolidation (%s Gwei) exceeds the maximum allowed (%s Gwei). '
            'You can override the limit using --max-consolidation-request-fee-gwei flag.',
            Web3.from_wei(consolidation_request_fee, 'gwei'),
            max_consolidation_request_fee_gwei,
        )
        return

    oracle_signatures = None
    if (
        len(target_source_public_keys) == 1
        and target_source_public_keys[0][0] == target_source_public_keys[0][1]
    ):
        # The oracles signatures are only required when switching from 0x01 to 0x02
        oracle_signatures = await poll_consolidation_signature(
            target_public_keys=[target_source_public_keys[0][0]],
            vault=settings.vault,
            protocol_config=protocol_config,
        )

    encoded_validators = _encode_validators(target_source_public_keys)
    validators_manager_signature = await _get_validators_manager_signature(
        target_source_public_keys
    )

    tx_hash = await submit_consolidate_validators(
        validators=encoded_validators,
        oracle_signatures=oracle_signatures,
        tx_fee=Wei(consolidation_request_fee * consolidations_count),
        validators_manager_signature=validators_manager_signature,
    )

    if tx_hash:
        click.secho(
            'Validators have been successfully consolidated',
            bold=True,
            fg='green',
        )


async def _check_validators_manager() -> None:
    if settings.relayer_endpoint:
        return
    vault_contract = VaultContract(settings.vault)
    validators_manager = await vault_contract.validators_manager()
    if validators_manager != wallet.account.address:
        raise click.ClickException(
            f'The Validators Manager role must be assigned to the address {wallet.account.address}.'
            f' Please update it in the vault settings.'
        )


async def _check_consolidations_queue(chain_head: ChainHead) -> None:
    queue_length = await get_consolidations_count(chain_head)
    if queue_length >= settings.network_config.PENDING_CONSOLIDATIONS_LIMIT:
        raise click.ClickException(
            'Pending consolidations queue has exceeded its limit. Please try again later.'
        )


def _encode_validators(target_source_public_keys: list[tuple[HexStr, HexStr]]) -> bytes:
    validators_data = b''
    for target_key, source_key in target_source_public_keys:
        validators_data += Web3.to_bytes(hexstr=source_key)
        validators_data += Web3.to_bytes(hexstr=target_key)
    return validators_data


def _load_public_keys(public_keys_file: Path) -> list[HexStr]:
    """Loads public keys from file."""
    with open(public_keys_file, 'r', encoding='utf-8') as f:
        public_keys = [add_0x_prefix(HexStr(line.rstrip())) for line in f]

    return public_keys


async def _get_validators_manager_signature(
    target_source_public_keys: list[tuple[HexStr, HexStr]]
) -> HexStr:
    if not settings.relayer_endpoint:
        return HexStr('0x')
    relayer = RelayerClient()
    # fetch validator manager signature from relayer
    relayer_response = await relayer.consolidate_validators(
        vault_address=settings.vault,
        target_source_public_keys=target_source_public_keys,
    )
    if not relayer_response.validators_manager_signature:
        raise click.ClickException('Could not get validator manager signature from relayer')

    return relayer_response.validators_manager_signature
