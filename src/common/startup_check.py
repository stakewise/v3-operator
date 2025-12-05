import asyncio
import logging
import socket
import time
from os import path
from pathlib import Path

import click
import psutil
from aiohttp import ClientSession, ClientTimeout
from click import ClickException
from sw_utils import (
    ChainHead,
    InterruptHandler,
    IpfsFetchClient,
    get_consensus_client,
    get_execution_client,
)
from sw_utils.graph.client import GraphClient as SWGraphClient
from sw_utils.pectra import get_pectra_vault_version
from web3 import Web3
from web3.exceptions import BadFunctionCallOutput

from src.common.clients import OPERATOR_USER_AGENT, db_client
from src.common.clients import execution_client as default_execution_client
from src.common.consensus import get_chain_finalized_head
from src.common.contracts import (
    VaultContract,
    keeper_contract,
    validators_registry_contract,
)
from src.common.execution import check_wallet_balance
from src.common.harvest import get_harvest_params
from src.common.protocol_config import get_protocol_config
from src.common.typings import ValidatorsRegistrationMode
from src.common.utils import format_error, round_down, warning_verbose
from src.common.wallet import wallet
from src.config.networks import NETWORKS
from src.config.settings import (
    DEFAULT_CONSENSUS_ENDPOINT,
    DEFAULT_EXECUTION_ENDPOINT,
    WITHDRAWALS_INTERVAL,
    settings,
)
from src.meta_vault.graph import graph_get_vaults
from src.validators.execution import get_withdrawable_assets
from src.validators.keystores.local import LocalKeystore
from src.validators.relayer import RelayerClient

logger = logging.getLogger(__name__)

IPFS_HASH_EXAMPLE = 'QmawUdo17Fvo7xa6ARCUSMV1eoVwPtVuzx8L8Crj2xozWm'


# pylint: disable-next=too-many-statements
async def startup_checks() -> None:
    logger.info('Checking connection to database...')
    db_client.create_db_dir()
    with db_client.get_db_connection() as conn:
        conn.cursor()
    logger.info('Connected to database %s.', settings.database)

    if settings.run_nodes:
        # Wait a bit for nodes to start
        await asyncio.sleep(10)

    logger.info('Checking connection to consensus nodes...')
    await wait_for_consensus_node()

    logger.info('Checking connection to execution nodes...')
    await wait_for_execution_node()

    logger.info('Checking consensus nodes network...')
    await _check_consensus_nodes_network()

    logger.info('Checking execution nodes network...')
    await _check_execution_nodes_network()

    logger.info('Checking that consensus and execution nodes are in sync...')
    chain_state = await get_chain_finalized_head()
    await wait_execution_catch_up_consensus(chain_state)

    logger.info('Checking execution nodes network...')
    await _check_execution_nodes_network()

    if settings.claim_fee_splitter or settings.process_meta_vault:
        logger.info('Checking graph nodes...')
        await wait_for_graph_node_sync_to_chain_head()

    logger.info('Checking oracles config...')
    await _check_events_logs()

    logger.info('Checking vault address %s...', settings.vault)
    await _check_vault_address()

    await _check_vault_withdrawable_assets()

    logger.info('Checking wallet balance %s...', wallet.address)
    await check_wallet_balance()

    logger.info('Checking connection to ipfs nodes...')
    healthy_ipfs_endpoints = await _check_ipfs_endpoints()

    logger.info('Connected to ipfs nodes at %s.', ', '.join(healthy_ipfs_endpoints))

    logger.info('Checking connection to oracles set...')
    healthy_oracles = await collect_healthy_oracles()
    logger.info('Connected to oracles at %s', ', '.join(healthy_oracles))

    await check_vault_version()

    if settings.enable_metrics:
        logger.info('Checking metrics server...')
        check_metrics_port()

    if (
        settings.validators_registration_mode == ValidatorsRegistrationMode.AUTO
        and settings.keystore_cls_str == LocalKeystore.__name__
        and not settings.disable_validators_registration
    ):
        logger.info('Checking keystores dir...')
        wait_for_keystores_dir()
        logger.info('Found keystores dir')

    await check_validators_manager()

    if settings.validators_registration_mode == ValidatorsRegistrationMode.API:
        logger.info('Checking Relayer endpoint %s...', settings.relayer_endpoint)
        await _check_relayer_endpoint()

    protocol_config = await get_protocol_config()
    if WITHDRAWALS_INTERVAL > protocol_config.force_withdrawals_period:
        raise ValueError(
            'WITHDRAWALS_INTERVAL setting should be less than '
            f'force withdrawals period({protocol_config.force_withdrawals_period} seconds)'
        )
    if settings.process_meta_vault:
        await _check_is_meta_vault()


def validate_settings() -> None:
    if not settings.execution_endpoints:
        raise ClickException('EXECUTION_ENDPOINTS is missing')

    if not settings.consensus_endpoints:
        raise ClickException('CONSENSUS_ENDPOINTS is missing')

    if not settings.graph_endpoint and (settings.claim_fee_splitter or settings.process_meta_vault):
        raise ClickException('GRAPH_ENDPOINT is missing')

    if settings.run_nodes and settings.execution_endpoints != [DEFAULT_EXECUTION_ENDPOINT]:
        raise ClickException(
            f'With --run-nodes enabled, --execution-endpoints should be '
            f'set to the default value: {DEFAULT_EXECUTION_ENDPOINT}'
        )

    if settings.run_nodes and settings.consensus_endpoints != [DEFAULT_CONSENSUS_ENDPOINT]:
        raise ClickException(
            f'With --run-nodes enabled, --consensus-endpoints should be '
            f'set to the default value: {DEFAULT_CONSENSUS_ENDPOINT}'
        )


async def wait_for_consensus_node() -> None:
    """
    Waits until at least one endpoint in the list of consensus endpoints is available
    """
    done = False
    while True:
        for consensus_endpoint in settings.consensus_endpoints:
            try:
                consensus_client = get_consensus_client(
                    [consensus_endpoint],
                    user_agent=OPERATOR_USER_AGENT,
                )
                syncing = await consensus_client.get_syncing()
                if syncing['data']['is_syncing'] is True:
                    logger.warning(
                        'The consensus node located at %s has not completed synchronization yet. '
                        'The remaining synchronization distance is %s.',
                        consensus_endpoint,
                        syncing['data']['sync_distance'],
                    )
                    continue
                data = await consensus_client.get_finality_checkpoint()
                logger.info(
                    'Connected to consensus node at %s. Finalized epoch: %s',
                    consensus_endpoint,
                    data['data']['finalized']['epoch'],
                )
                done = True
            except Exception as e:
                logger.warning(
                    'Failed to connect to consensus node at %s. %s',
                    consensus_endpoint,
                    e,
                )
        if done:
            return
        logger.warning('Consensus nodes are not ready. Retrying in 10 seconds...')
        await asyncio.sleep(10)


async def wait_for_execution_node() -> None:
    """
    Waits until at least one endpoint in the list of execution endpoints is available
    """
    done = False
    while True:
        for execution_endpoint in settings.execution_endpoints:
            try:
                execution_client = get_execution_client(
                    [execution_endpoint],
                    jwt_secret=settings.execution_jwt_secret,
                    user_agent=OPERATOR_USER_AGENT,
                )

                syncing = await execution_client.eth.syncing
                if syncing is True:
                    logger.warning(
                        'The execution node located at %s has not completed synchronization yet.',
                        execution_endpoint,
                    )
                    continue
                block_number = await execution_client.eth.block_number
                if block_number <= 0:
                    # There was a case when `block_number` equals to 0 although `syncing` is False.
                    logger.warning(
                        'Execution node %s. Current block number is %s',
                        execution_endpoint,
                        block_number,
                    )
                    continue
                logger.info(
                    'Connected to execution node at %s. Current block number: %s',
                    execution_endpoint,
                    block_number,
                )
                done = True
            except Exception as e:
                logger.warning(
                    'Failed to connect to execution node at %s. %s',
                    execution_endpoint,
                    e,
                )
        if done:
            return
        logger.warning('Execution nodes are not ready. Retrying in 10 seconds...')
        await asyncio.sleep(10)


async def wait_execution_catch_up_consensus(
    chain_head: ChainHead, interrupt_handler: InterruptHandler | None = None
) -> None:
    """
    Consider execution and consensus nodes are working independently of each other.
    Check execution node is synced to the consensus finalized block.
    """
    execution_client = default_execution_client

    while True:
        if interrupt_handler and interrupt_handler.exit:
            return

        execution_block_number = await execution_client.eth.get_block_number()
        if execution_block_number >= chain_head.block_number:
            return

        logger.warning(
            'The execution client is behind the consensus client: '
            'execution block %d, consensus finalized block %d, distance %d blocks',
            execution_block_number,
            chain_head.block_number,
            chain_head.block_number - execution_block_number,
        )
        sleep_time = float(settings.network_config.SECONDS_PER_BLOCK)

        if interrupt_handler:
            await interrupt_handler.sleep(sleep_time)
        else:
            await asyncio.sleep(sleep_time)


async def wait_for_graph_node_sync_to_chain_head() -> None:
    """
    Waits until graph node is available and synced to the finalized head of the chain.
    """
    # Create non-retry graph client
    graph_client = SWGraphClient(
        endpoint=settings.graph_endpoint,
        request_timeout=settings.graph_request_timeout,
        retry_timeout=0,
        page_size=settings.graph_page_size,
    )
    chain_state = await get_chain_finalized_head()
    graph_block_number = await graph_client.get_last_synced_block()

    while graph_block_number < chain_state.block_number:
        logger.warning(
            'The graph node located at %s has not completed synchronization yet.',
            settings.graph_endpoint,
        )
        await asyncio.sleep(settings.network_config.SECONDS_PER_BLOCK)
        chain_state = await get_chain_finalized_head()
        graph_block_number = await graph_client.get_last_synced_block()


async def collect_healthy_oracles() -> list:
    oracles = (await get_protocol_config()).oracles
    endpoints = [oracle.endpoints for oracle in oracles]

    async with ClientSession(timeout=ClientTimeout(60)) as session:
        results = await asyncio.gather(
            *[
                _aiohttp_fetch(session=session, url=endpoint)
                for replicas in endpoints
                for endpoint in replicas
            ],
            return_exceptions=True,
        )

    healthy_oracles = []
    for result, endpoint in zip(results, endpoints):
        if isinstance(result, Exception):
            warning_verbose('%s for endpoint %s', format_error(result), endpoint)
            continue

        if result:
            healthy_oracles.append(result)

    return healthy_oracles


def check_metrics_port() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        result = sock.connect_ex((settings.metrics_host, settings.metrics_port))
        if result != 0:
            break
        logger.warning(
            "Can't start metrics server at %s:%s. Port is busy. Retrying in 10 seconds...",
            settings.metrics_host,
            settings.metrics_port,
        )
        time.sleep(10)
    sock.close()


def wait_for_keystores_dir() -> None:
    while not path.exists(settings.keystores_dir):
        logger.warning(
            "Can't find keystores directory (%s)",
            settings.keystores_dir,
        )
        time.sleep(15)


async def _check_consensus_nodes_network() -> None:
    """
    Checks that consensus node network is the same as settings.network
    """
    chain_id_to_network = _get_chain_id_to_network_dict()
    for consensus_endpoint in settings.consensus_endpoints:
        consensus_client = get_consensus_client(
            [consensus_endpoint], user_agent=OPERATOR_USER_AGENT
        )
        deposit_contract_data = (await consensus_client.get_deposit_contract())['data']
        consensus_chain_id = int(deposit_contract_data['chain_id'])
        consensus_network = chain_id_to_network.get(consensus_chain_id)
        if settings.network_config.CHAIN_ID != consensus_chain_id:
            raise ValueError(
                f'Consensus node network is {consensus_network or 'unknown'}, '
                f'while {settings.network} is set in the vault config.'
            )


async def _check_execution_nodes_network() -> None:
    """
    Checks that execution node network is the same as settings.network
    """
    chain_id_to_network = _get_chain_id_to_network_dict()
    for execution_endpoint in settings.execution_endpoints:
        execution_client = get_execution_client(
            [execution_endpoint],
            jwt_secret=settings.execution_jwt_secret,
            user_agent=OPERATOR_USER_AGENT,
        )
        execution_chain_id = await execution_client.eth.chain_id
        execution_network = chain_id_to_network.get(execution_chain_id)
        if settings.network_config.CHAIN_ID != execution_chain_id:
            raise ValueError(
                f'Execution node network is {execution_network or 'unknown'}, '
                f'while {settings.network}  is set in the vault config.'
            )


def _get_chain_id_to_network_dict() -> dict[int, str]:
    chain_id_to_network: dict[int, str] = {}
    for network, network_config in NETWORKS.items():
        chain_id_to_network[network_config.CHAIN_ID] = network
    return chain_id_to_network


async def _aiohttp_fetch(session: ClientSession, url: str) -> str:
    async with session.get(url=url) as response:
        response.raise_for_status()
    return url


async def _check_ipfs_endpoints() -> list[str]:
    healthy_ipfs_endpoints = []

    for endpoint in settings.ipfs_fetch_endpoints:
        client = IpfsFetchClient([endpoint])
        try:
            await client.fetch_json(IPFS_HASH_EXAMPLE)
        except Exception as e:
            logger.warning("Can't connect to ipfs node %s: %s", endpoint, e)
        else:
            healthy_ipfs_endpoints.append(endpoint)

    return healthy_ipfs_endpoints


async def check_validators_manager() -> None:
    if settings.validators_registration_mode != ValidatorsRegistrationMode.AUTO:
        return
    vault_contract = VaultContract(settings.vault)
    validators_manager = await vault_contract.validators_manager()
    if validators_manager != wallet.account.address:
        raise RuntimeError(
            f'The Validators Manager role must be assigned to the address {wallet.account.address}'
            f' for the vault {settings.vault}. Please update it in the vault settings.'
        )


async def check_vault_version() -> None:
    vault_contract = VaultContract(settings.vault)
    if await vault_contract.version() < get_pectra_vault_version(settings.network, settings.vault):
        raise RuntimeError(f'Please upgrade Vault {settings.vault} to the latest version.')


async def _check_events_logs() -> None:
    """Check that EL client didn't prune logs"""
    events = await keeper_contract.events.ConfigUpdated.get_logs(  # type: ignore
        fromBlock=settings.network_config.CONFIG_UPDATE_EVENT_BLOCK,
        toBlock=settings.network_config.CONFIG_UPDATE_EVENT_BLOCK,
    )
    if not events:
        raise ValueError(
            "Can't find oracle config. Please, ensure that EL client didn't prune event logs."
        )

    events = await validators_registry_contract.events.DepositEvent.get_logs(  # type: ignore
        fromBlock=settings.network_config.GENESIS_VALIDATORS_LAST_BLOCK,
        toBlock=settings.network_config.GENESIS_VALIDATORS_LAST_BLOCK,
    )
    if not events:
        raise ValueError(
            "Can't find network validator events. "
            "Please, ensure that EL client didn't prune event logs."
        )


async def _check_vault_withdrawable_assets() -> None:
    harvest_params = await get_harvest_params()
    withdrawable_assets = await get_withdrawable_assets(harvest_params=harvest_params)

    # Note. We round down assets in the log message because of the case when assets
    # is slightly less than required amount to register validator.
    # Standard rounding will show that we have enough assets, but in fact we don't.
    logger.info(
        'Vault withdrawable assets: %s %s',
        round_down(Web3.from_wei(withdrawable_assets, 'ether'), 2),
        settings.network_config.VAULT_BALANCE_SYMBOL,
    )


async def _check_relayer_endpoint() -> None:
    info = await RelayerClient().get_info()

    relayer_network = info['network']
    if relayer_network != settings.network:
        raise ValueError(
            f'Relayer network "{relayer_network}" does not match '
            f'Operator network "{settings.network}"'
        )


async def _check_vault_address() -> None:
    try:
        await VaultContract(address=settings.vault).version()
    except BadFunctionCallOutput as e:
        raise ClickException(f'Invalid vault contract address {settings.vault}') from e


async def _check_is_meta_vault() -> None:
    meta_vaults = await graph_get_vaults(is_meta_vault=True)
    if settings.vault not in meta_vaults:
        raise ValueError(f'Vault {settings.vault} is not a meta vault')


def check_hardware_requirements(data_dir: Path, network: str, no_confirm: bool) -> None:
    # Check memory requirements
    mem = psutil.virtual_memory()
    mem_total_gb = mem.total / (1024**3)
    min_memory_gb = NETWORKS[network].NODE_CONFIG.MIN_MEMORY_GB

    if mem_total_gb < min_memory_gb:
        if not no_confirm and not click.confirm(
            f'At least {min_memory_gb} GB of RAM is recommended to run the nodes.\n'
            f'You have {mem_total_gb:.1f} GB of RAM in total.\n'
            f'Do you want to continue anyway?',
            default=False,
        ):
            raise click.Abort()

    # Check disk space requirements
    disk_usage = psutil.disk_usage(str(data_dir))
    disk_total_tb = disk_usage.total / (1024**4)
    min_disk_tb = NETWORKS[network].NODE_CONFIG.MIN_DISK_SPACE_TB

    if disk_total_tb < min_disk_tb:
        if not no_confirm and not click.confirm(
            f'At least {min_disk_tb} TB of disk space is recommended in the data directory.\n'
            f'You have {disk_total_tb:.1f} TB available at {data_dir}.\n'
            f'Do you want to continue anyway?',
            default=False,
        ):
            raise click.Abort()
