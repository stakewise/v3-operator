import asyncio
import logging

from src.common.clients import db_client
from src.common.consensus import get_chain_finalized_head
from src.common.execution import check_wallet_balance
from src.common.protocol_config import get_protocol_config
from src.common.startup_check import (
    check_consensus_nodes_network,
    check_events_logs,
    check_execution_nodes_network,
    check_ipfs_endpoints,
    check_metrics_port,
    check_relayer_endpoint,
    check_validators_manager,
    check_vault_address,
    check_vault_version,
    check_vault_withdrawable_assets,
    collect_healthy_oracles,
    validate_settings,
    wait_execution_catch_up_consensus,
    wait_for_consensus_node,
    wait_for_execution_node,
    wait_for_graph_node_sync_to_chain_head,
    wait_for_keystores_dir,
)
from src.common.wallet import wallet
from src.config.settings import WITHDRAWALS_INTERVAL, settings
from src.validators.keystores.local import LocalKeystore

logger = logging.getLogger(__name__)


# pylint: disable-next=too-many-statements
async def startup_checks() -> None:
    validate_settings()

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
    await check_consensus_nodes_network()

    logger.info('Checking execution nodes network...')
    await check_execution_nodes_network()

    logger.info('Checking that consensus and execution nodes are in sync...')
    chain_state = await get_chain_finalized_head()
    await wait_execution_catch_up_consensus(chain_state)

    if settings.claim_fee_splitter:
        logger.info('Checking graph nodes...')
        await wait_for_graph_node_sync_to_chain_head()

    logger.info('Checking oracles config...')
    await check_events_logs()

    logger.info('Checking vault address %s...', settings.vault)
    await check_vault_address()

    await check_vault_withdrawable_assets()

    logger.info('Checking wallet balance %s...', wallet.address)
    await check_wallet_balance()

    logger.info('Checking connection to ipfs nodes...')
    healthy_ipfs_endpoints = await check_ipfs_endpoints()

    logger.info('Connected to ipfs nodes at %s.', ', '.join(healthy_ipfs_endpoints))

    logger.info('Checking connection to oracles set...')
    healthy_oracles = await collect_healthy_oracles()
    logger.info('Connected to oracles at %s', ', '.join(healthy_oracles))

    await check_vault_version()

    if settings.enable_metrics:
        logger.info('Checking metrics server...')
        check_metrics_port()

    if (
        not settings.relayer_endpoint
        and settings.keystore_cls_str == LocalKeystore.__name__
        and not settings.disable_validators_registration
    ):
        logger.info('Checking keystores dir...')
        wait_for_keystores_dir()
        logger.info('Found keystores dir')

    await check_validators_manager()

    if settings.relayer_endpoint:
        logger.info('Checking Relayer endpoint %s...', settings.relayer_endpoint)
        await check_relayer_endpoint()

    protocol_config = await get_protocol_config()
    if WITHDRAWALS_INTERVAL > protocol_config.force_withdrawals_period:
        raise ValueError(
            'WITHDRAWALS_INTERVAL setting should be less than '
            f'force withdrawals period({protocol_config.force_withdrawals_period} seconds)'
        )
