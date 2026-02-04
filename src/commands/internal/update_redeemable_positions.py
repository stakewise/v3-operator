import asyncio
import logging
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import click
from eth_typing import BlockNumber, ChecksumAddress
from multiproof import StandardMerkleTree
from web3 import Web3
from web3.types import Gwei, Wei

from src.common.clients import (
    build_ipfs_upload_clients,
    close_clients,
    execution_client,
    get_execution_client,
    setup_clients,
)
from src.common.contracts import Erc20Contract, os_token_redeemer_contract
from src.common.logging import LOG_LEVELS, setup_logging
from src.common.utils import log_verbose
from src.config.networks import (
    AVAILABLE_NETWORKS,
    GNOSIS,
    MAINNET,
    ZERO_CHECKSUM_ADDRESS,
)
from src.config.settings import settings
from src.redemptions.api_client import API_SLEEP_TIMEOUT, APIClient
from src.redemptions.graph import (
    graph_get_allocators,
    graph_get_leverage_positions,
    graph_get_os_token_holders,
)
from src.redemptions.os_token_converter import (
    OsTokenConverter,
    create_os_token_converter,
)
from src.redemptions.typings import (
    Allocator,
    ArbitrumConfig,
    LeverageStrategyPosition,
    RedeemablePosition,
)

logger = logging.getLogger(__name__)


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
    '--min-os-token-position-amount-gwei',
    type=int,
    default=0,
    envvar='MIN_OS_TOKEN_POSITION_AMOUNT_GWEI',
    help='Process positions only if the amount of minted os token in Gwei'
    ' is greater than the specified value.',
)
@click.option(
    '--execution-endpoints',
    type=str,
    envvar='EXECUTION_ENDPOINTS',
    prompt='Enter the comma separated list of API endpoints for execution nodes',
    help='Comma separated list of API endpoints for execution nodes.',
)
@click.option(
    '--execution-jwt-secret',
    type=str,
    envvar='EXECUTION_JWT_SECRET',
    help='JWT secret key used for signing and verifying JSON Web Tokens'
    ' when connecting to execution nodes.',
)
@click.option(
    '--graph-endpoint',
    type=str,
    envvar='GRAPH_ENDPOINT',
    help='API endpoint for graph node.',
)
@click.option(
    '--arbitrum-endpoint',
    type=str,
    envvar='ARBITRUM_ENDPOINT',
    help='API endpoint for the execution node on Arbitrum.',
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
    '-v',
    '--verbose',
    help='Enable debug mode. Default is false.',
    envvar='VERBOSE',
    is_flag=True,
)
@click.option(
    '--network',
    help='The network of the meta vaults.',
    prompt='Enter the network name',
    envvar='NETWORK',
    type=click.Choice(
        AVAILABLE_NETWORKS,
        case_sensitive=False,
    ),
)
@click.command(help='Updates redeemable positions')
# pylint: disable-next=too-many-arguments
def update_redeemable_positions(
    execution_endpoints: str,
    execution_jwt_secret: str | None,
    graph_endpoint: str,
    arbitrum_endpoint: str | None,
    network: str,
    verbose: bool,
    log_level: str,
    wallet_file: str | None,
    wallet_password_file: str | None,
    min_os_token_position_amount_gwei: int,
) -> None:
    settings.set(
        vault=ZERO_CHECKSUM_ADDRESS,
        vault_dir=Path.home() / '.stakewise',
        execution_endpoints=execution_endpoints,
        execution_jwt_secret=execution_jwt_secret,
        graph_endpoint=graph_endpoint,
        verbose=verbose,
        network=network,
        wallet_file=wallet_file,
        wallet_password_file=wallet_password_file,
        log_level=log_level,
    )
    arbitrum_config: ArbitrumConfig | None = None
    if network == MAINNET:
        if not arbitrum_endpoint:
            raise click.BadParameter('arbitrum-endpoint is required for mainnet network')
        arbitrum_config = ArbitrumConfig(
            OS_TOKEN_CONTRACT_ADDRESS=settings.network_config.OS_TOKEN_ARBITRUM_CONTRACT_ADDRESS,
            EXECUTION_ENDPOINT=arbitrum_endpoint,
        )
    try:
        # Try-catch to enable async calls in test - an event loop
        #  will already be running in that case
        try:
            asyncio.get_running_loop()
            # we need to create a separate thread so we can block before returning
            with ThreadPoolExecutor(1) as pool:
                pool.submit(
                    lambda: asyncio.run(
                        main(
                            arbitrum_config=arbitrum_config,
                            min_os_token_position_amount_gwei=Gwei(
                                min_os_token_position_amount_gwei
                            ),
                        )
                    )
                ).result()
        except RuntimeError as e:
            if 'no running event loop' == e.args[0]:
                # no event loop running
                asyncio.run(
                    main(
                        arbitrum_config=arbitrum_config,
                        min_os_token_position_amount_gwei=Gwei(min_os_token_position_amount_gwei),
                    )
                )
            else:
                raise e
    except Exception as e:
        log_verbose(e)
        sys.exit(1)


async def main(
    arbitrum_config: ArbitrumConfig | None, min_os_token_position_amount_gwei: Gwei
) -> None:
    setup_logging()
    await setup_clients()
    try:
        await process(
            arbitrum_config=arbitrum_config,
            min_os_token_position_amount_gwei=min_os_token_position_amount_gwei,
        )
    finally:
        await close_clients()


# pylint: disable-next=too-many-locals
async def process(
    arbitrum_config: ArbitrumConfig | None, min_os_token_position_amount_gwei: Gwei
) -> None:
    """
    Fetch redeemable positions, calculate kept os token amounts and upload to IPFS.
    """
    block_number = await execution_client.eth.get_block_number()
    logger.info('Fetching allocators from the subgraph...')
    allocators = await graph_get_allocators(block_number)
    logger.info('Fetched %s allocators from the subgraph', len(allocators))

    # filter boost proxy positions
    logger.info('Fetching boosted positions from the subgraph...')
    leverage_positions = await graph_get_leverage_positions(block_number)
    boost_proxies = {pos.proxy for pos in leverage_positions}
    logger.info('Found %s proxy positions to exclude', len(boost_proxies))
    allocators = [a for a in allocators if a.address not in boost_proxies]
    # reduce boosted positions
    os_token_converter = await create_os_token_converter(block_number)
    boost_ostoken_shares = await calculate_boost_ostoken_shares(
        users={a.address for a in allocators},
        leverage_positions=leverage_positions,
        os_token_converter=os_token_converter,
    )
    allocators = _reduce_boosted_amount(allocators, boost_ostoken_shares)

    # filter zero positions. Filter before kept shares calculation to reduce api calls
    min_minted_shares = Web3.to_wei(min_os_token_position_amount_gwei, 'gwei')
    for allocator in allocators:
        allocator.vault_shares = [
            vault_share
            for vault_share in allocator.vault_shares
            if vault_share.minted_shares >= min_minted_shares
        ]

    if not allocators:
        logger.info('No allocators with minted shares above the threshold found, exiting...')
        return

    logger.info('Fetching kept tokens for %s addresses', len(allocators))
    address_to_minted_shares = {a.address: a.total_shares for a in allocators}
    kept_shares = await get_kept_shares(address_to_minted_shares, block_number, arbitrum_config)
    logger.info('Fetched kept tokens for %s addresses...', len(address_to_minted_shares))

    redeemable_positions = create_redeemable_positions(allocators, kept_shares, min_minted_shares)
    if not redeemable_positions:
        logger.info('No redeemable positions to upload, exiting...')
        return
    total_redeemable = sum(p.amount for p in redeemable_positions)
    logger.info(
        'Created %(count)s redeemable positions. Total redeemed %(os_token_symbol)s amount: '
        '%(total_redeemable)s (%(total_redeemable_eth).5f %(os_token_symbol)s)',
        {
            'count': len(redeemable_positions),
            'os_token_symbol': settings.network_config.OS_TOKEN_BALANCE_SYMBOL,
            'total_redeemable': total_redeemable,
            'total_redeemable_eth': Web3.from_wei(total_redeemable, 'ether'),
        },
    )

    click.confirm(
        'Proceed with uploading redeemable positions to IPFS?',
        default=True,
        abort=True,
    )
    ipfs_upload_client = build_ipfs_upload_clients()
    ipfs_hash = await ipfs_upload_client.upload_json([p.as_dict() for p in redeemable_positions])
    click.echo(f'Redeemable position uploaded to IPFS: hash={ipfs_hash}')

    # calculate merkle root
    nonce = await os_token_redeemer_contract.nonce()
    leaves = [r.merkle_leaf(nonce) for r in redeemable_positions]
    tree = StandardMerkleTree.of(
        leaves,
        [
            'uint256',
            'address',
            'uint256',
            'address',
        ],
    )
    click.echo(f'Generated Merkle Tree root: {tree.root}')


async def get_kept_shares(
    address_to_minted_shares: dict[ChecksumAddress, Wei],
    block_number: BlockNumber,
    arbitrum_config: ArbitrumConfig | None,
) -> dict[ChecksumAddress, Wei]:
    kept_shares = defaultdict(lambda: Wei(0))
    logger.info(
        'Fetching %s balances from the subgraph...', settings.network_config.OS_TOKEN_BALANCE_SYMBOL
    )
    os_token_holders = await graph_get_os_token_holders(block_number)
    for address in address_to_minted_shares.keys():
        kept_shares[address] = os_token_holders.get(address, Wei(0))

    # arb wallet balance
    if arbitrum_config:
        logger.info(
            'Fetching %s from Arbitrum wallet balances...',
            settings.network_config.OS_TOKEN_BALANCE_SYMBOL,
        )
        arbitrum_endpoint = arbitrum_config.EXECUTION_ENDPOINT
        arb_execution_client = get_execution_client([arbitrum_endpoint])
        try:
            arb_contract = Erc20Contract(
                settings.network_config.OS_TOKEN_ARBITRUM_CONTRACT_ADDRESS,
                execution_client=arb_execution_client,
            )
            for index, address in enumerate(address_to_minted_shares.keys()):
                if index and index % 50 == 0:
                    logger.info(
                        'Fetched wallet balances for %d/%d addresses',
                        index,
                        len(address_to_minted_shares),
                    )
                arb_balance = await arb_contract.get_balance(address)
                kept_shares[address] = Wei(kept_shares[address] + arb_balance)
        finally:
            await arb_execution_client.provider.disconnect()

    # rabby doesnt support hoodi so skip api call
    if settings.network not in [MAINNET, GNOSIS]:
        return kept_shares

    # do not fetch data from api if all os token are in the wallet
    api_addresses = []
    for address in address_to_minted_shares.keys():
        if address_to_minted_shares[address] >= kept_shares[address]:
            api_addresses.append(address)

    if not api_addresses:
        return kept_shares

    logger.info(
        'Fetching locked %s from DeBank API for %s addresses...',
        settings.network_config.OS_TOKEN_BALANCE_SYMBOL,
        len(api_addresses),
    )
    api_client = APIClient()
    # fetch locked os token from the api
    with click.progressbar(
        api_addresses,
        label='Fetching os token amount locked in protocols from the api:\t\t',
        show_percent=False,
        show_pos=True,
    ) as progress_bar:
        for index, address in enumerate(progress_bar):
            if index:
                await asyncio.sleep(API_SLEEP_TIMEOUT)  # to avoid rate limiting
            locked_os_token = await api_client.get_protocols_locked_os_token(address=address)
            kept_shares[address] = Wei(kept_shares[address] + locked_os_token)
    return kept_shares


async def calculate_boost_ostoken_shares(
    users: set[ChecksumAddress],
    leverage_positions: list[LeverageStrategyPosition],
    os_token_converter: OsTokenConverter,
) -> dict[tuple[ChecksumAddress, ChecksumAddress], Wei]:
    boosted_positions: defaultdict[tuple[ChecksumAddress, ChecksumAddress], Wei] = defaultdict(
        lambda: Wei(0)
    )
    if not leverage_positions:
        return boosted_positions

    for position in leverage_positions:
        if position.user not in users:
            continue
        position_os_token_shares = Wei(
            position.os_token_shares
            + position.exiting_os_token_shares
            + os_token_converter.to_shares(position.assets)
            + os_token_converter.to_shares(position.exiting_assets)
        )
        boosted_positions[position.user, position.vault] = Wei(
            boosted_positions[position.user, position.vault] + position_os_token_shares
        )

    return boosted_positions


def create_redeemable_positions(
    allocators: list[Allocator],
    kept_shares: dict[ChecksumAddress, Wei],
    min_minted_shares: Wei,
) -> list[RedeemablePosition]:
    """
    Calculate vault proportions and create redeemable positions.
    Sort by amount descending.
    """
    redeemable_positions: list[RedeemablePosition] = []
    for allocator in allocators:
        allocator_kept_shares = kept_shares.get(allocator.address, Wei(0))
        redeemable_amount = max(0, allocator.total_shares - allocator_kept_shares)
        if redeemable_amount == 0:
            continue

        allocated_amount = 0
        vaults_proportions = allocator.vaults_proportions.items()
        for index, (vault_address, proportion) in enumerate(vaults_proportions):
            # dust handling
            if index == len(vaults_proportions) - 1:
                vault_amount = max(0, int(redeemable_amount - allocated_amount))
            else:
                vault_amount = int(redeemable_amount * proportion)
            allocated_amount += vault_amount
            if vault_amount < min_minted_shares:
                continue
            redeemable_positions.append(
                RedeemablePosition(
                    owner=allocator.address,
                    vault=vault_address,
                    amount=Wei(vault_amount),
                )
            )
    redeemable_positions.sort(key=lambda p: p.amount, reverse=True)
    return redeemable_positions


def _reduce_boosted_amount(
    allocators: list[Allocator],
    boost_ostoken_shares: dict[tuple[ChecksumAddress, ChecksumAddress], Wei],
) -> list[Allocator]:
    for allocator in allocators:
        for vault_share in allocator.vault_shares:
            key = allocator.address, vault_share.address
            boosted_amount = boost_ostoken_shares.get(key, Wei(0))
            vault_share.minted_shares = Wei(max(0, vault_share.minted_shares - boosted_amount))
    return allocators
