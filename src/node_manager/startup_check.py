import asyncio
import logging

from click import ClickException
from eth_typing import ChecksumAddress

from src.common.clients import db_client
from src.common.consensus import get_chain_finalized_head
from src.common.contracts import nodes_manager_contract
from src.common.execution import check_wallet_balance
from src.common.startup_check import (
    check_consensus_nodes_network,
    check_events_logs,
    check_execution_nodes_network,
    check_ipfs_endpoints,
    check_metrics_port,
    collect_healthy_oracles,
    validate_settings,
    wait_execution_catch_up_consensus,
    wait_for_consensus_node,
    wait_for_execution_node,
    wait_for_keystores_dir,
)
from src.common.wallet import wallet
from src.config.settings import settings

logger = logging.getLogger(__name__)


async def startup_checks(withdrawals_address: ChecksumAddress) -> None:
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

    logger.info('Checking oracles config...')
    await check_events_logs()

    logger.info('Checking wallet balance %s...', wallet.address)
    await check_wallet_balance()

    logger.info('Checking connection to ipfs nodes...')
    healthy_ipfs_endpoints = await check_ipfs_endpoints()

    logger.info('Connected to ipfs nodes at %s.', ', '.join(healthy_ipfs_endpoints))

    logger.info('Checking connection to oracles set...')
    healthy_oracles = await collect_healthy_oracles()
    logger.info('Connected to oracles at %s', ', '.join(healthy_oracles))

    if settings.enable_metrics:
        logger.info('Checking metrics server...')
        check_metrics_port()

    logger.info('Checking keystores dir...')
    wait_for_keystores_dir()
    logger.info('Found keystores dir')

    await _check_validators_manager(withdrawals_address)

    await _check_community_vault()


async def _check_community_vault() -> None:
    nodes_manager_vault = await nodes_manager_contract.vault()
    if settings.network_config.COMMUNITY_VAULT_CONTRACT_ADDRESS != nodes_manager_vault:
        raise ClickException(
            f'Invalid community vault contract address: expected '
            f'{settings.network_config.COMMUNITY_VAULT_CONTRACT_ADDRESS}, got {nodes_manager_vault}'
        )


async def _check_validators_manager(withdrawals_address: ChecksumAddress) -> None:
    validators_manager = await nodes_manager_contract.validators_manager(withdrawals_address)

    if validators_manager != wallet.account.address:
        raise ClickException(
            f'The Validators Manager role must be assigned to the address {wallet.account.address}'
        )
