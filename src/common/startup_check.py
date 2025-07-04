import asyncio
import logging
import socket
import time
from os import path

from aiohttp import ClientSession, ClientTimeout
from sw_utils import IpfsFetchClient, get_consensus_client, get_execution_client
from web3 import Web3

from src.common.clients import OPERATOR_USER_AGENT, db_client
from src.common.contracts import (
    keeper_contract,
    validators_registry_contract,
    vault_contract,
)
from src.common.execution import (
    check_hot_wallet_balance,
    check_vault_address,
    get_protocol_config,
)
from src.common.harvest import get_harvest_params
from src.common.utils import format_error, round_down, warning_verbose
from src.common.wallet import hot_wallet
from src.config.networks import NETWORKS
from src.config.settings import settings
from src.validators.execution import check_deposit_data_root, get_withdrawable_assets
from src.validators.keystores.local import LocalKeystore
from src.validators.relayer import DvtRelayerClient
from src.validators.typings import RelayerTypes, ValidatorsRegistrationMode
from src.validators.utils import load_deposit_data

logger = logging.getLogger(__name__)

IPFS_HASH_EXAMPLE = 'QmawUdo17Fvo7xa6ARCUSMV1eoVwPtVuzx8L8Crj2xozWm'


async def startup_checks() -> None:
    validate_settings()

    logger.info('Checking connection to database...')
    db_client.create_db_dir()
    with db_client.get_db_connection() as conn:
        conn.cursor()
    logger.info('Connected to database %s.', settings.database)

    logger.info('Checking connection to consensus nodes...')
    await wait_for_consensus_node()

    logger.info('Checking connection to execution nodes...')
    await wait_for_execution_node()

    logger.info('Checking consensus nodes network...')
    await _check_consensus_nodes_network()

    logger.info('Checking execution nodes network...')
    await _check_execution_nodes_network()

    logger.info('Checking oracles config...')
    await _check_events_logs()

    logger.info('Checking vault address %s...', settings.vault)
    await check_vault_address()

    harvest_params = await get_harvest_params()
    withdrawable_assets = await get_withdrawable_assets(harvest_params)

    # Note. We round down assets in the log message because of the case when assets
    # is slightly less than required amount to register validator.
    # Standard rounding will show that we have enough assets, but in fact we don't.
    logger.info(
        'Vault withdrawable assets: %s %s',
        round_down(Web3.from_wei(withdrawable_assets, 'ether'), 2),
        settings.network_config.VAULT_BALANCE_SYMBOL,
    )

    logger.info('Checking hot wallet balance %s...', hot_wallet.address)
    await check_hot_wallet_balance()

    logger.info('Checking connection to ipfs nodes...')
    healthy_ipfs_endpoints = await _check_ipfs_endpoints()

    logger.info('Connected to ipfs nodes at %s.', ', '.join(healthy_ipfs_endpoints))

    logger.info('Checking connection to oracles set...')
    healthy_oracles = await collect_healthy_oracles()
    logger.info('Connected to oracles at %s', ', '.join(healthy_oracles))

    if settings.enable_metrics:
        logger.info('Checking metrics server...')
        check_metrics_port()

    if settings.need_deposit_data_file:
        logger.info('Checking deposit data file...')
        await wait_for_deposit_data_file()

    if (
        settings.validators_registration_mode == ValidatorsRegistrationMode.AUTO
        and settings.keystore_cls_str == LocalKeystore.__name__
    ):
        logger.info('Checking keystores dir...')
        wait_for_keystores_dir()
        logger.info('Found keystores dir')

    await _check_validators_manager()

    if (
        settings.validators_registration_mode == ValidatorsRegistrationMode.API
        and settings.relayer_type == RelayerTypes.DVT
    ):
        logger.info('Checking DVT Relayer endpoint %s...', settings.relayer_endpoint)
        await _check_dvt_relayer_endpoint()


def validate_settings() -> None:
    if not settings.execution_endpoints:
        raise ValueError('EXECUTION_ENDPOINTS is missing')

    if not settings.consensus_endpoints:
        raise ValueError('CONSENSUS_ENDPOINTS is missing')


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
        logger.warning('Failed to connect to consensus nodes. Retrying in 10 seconds...')
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
        logger.warning('Failed to connect to execution nodes. Retrying in 10 seconds...')
        await asyncio.sleep(10)


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


async def wait_for_deposit_data_file() -> None:
    while not path.exists(settings.deposit_data_file):
        logger.warning("Can't find deposit data file (%s)", settings.deposit_data_file)
        time.sleep(15)
    deposit_data = load_deposit_data(settings.vault, settings.deposit_data_file)
    logger.info('Found deposit data file %s', settings.deposit_data_file)

    if not settings.disable_deposit_data_warnings:
        while True:
            try:
                await check_deposit_data_root(deposit_data.tree.root)
                break
            except RuntimeError as e:
                logger.warning(e)
                time.sleep(15)


async def _check_consensus_nodes_network() -> None:
    """
    Checks that consensus node network is the same as settings.network
    """
    chain_id_to_network = get_chain_id_to_network_dict()
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
                f'while {settings.network} is passed in "--network" parameter'
            )


async def _check_execution_nodes_network() -> None:
    """
    Checks that execution node network is the same as settings.network
    """
    chain_id_to_network = get_chain_id_to_network_dict()
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
                f'while {settings.network} is passed in "--network" parameter'
            )


def get_chain_id_to_network_dict() -> dict[int, str]:
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


async def _check_validators_manager() -> None:
    if settings.validators_registration_mode == ValidatorsRegistrationMode.AUTO:
        if await vault_contract.version() > 1:
            validators_manager = await vault_contract.validators_manager()
            if validators_manager != settings.network_config.DEPOSIT_DATA_REGISTRY_CONTRACT_ADDRESS:
                raise RuntimeError(
                    'validators manager address must equal to deposit data registry address'
                )


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


async def _check_dvt_relayer_endpoint() -> None:
    info = await DvtRelayerClient().get_info()

    relayer_network = info['network']
    if relayer_network != settings.network:
        raise ValueError(
            f'Relayer network "{relayer_network}" does not match '
            f'Operator network "{settings.network}"'
        )
