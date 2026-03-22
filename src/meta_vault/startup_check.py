import logging

from click import ClickException
from eth_typing import ChecksumAddress

from src.common.execution import check_wallet_balance
from src.common.startup_check import (
    check_execution_nodes_network,
    wait_for_execution_node,
    wait_for_graph_node_sync_to_chain_head,
)
from src.common.wallet import wallet
from src.meta_vault.graph import graph_get_vaults

logger = logging.getLogger(__name__)


async def startup_checks(meta_vault_addresses: list[ChecksumAddress]) -> None:
    logger.info('Checking connection to execution nodes...')
    await wait_for_execution_node()

    logger.info('Checking execution nodes network...')
    await check_execution_nodes_network()

    logger.info('Checking graph nodes...')
    await wait_for_graph_node_sync_to_chain_head()

    logger.info('Checking meta vault addresses %s...', ', '.join(meta_vault_addresses))
    await _check_meta_vaults(meta_vault_addresses)

    logger.info('Checking wallet balance %s...', wallet.address)
    await check_wallet_balance()


async def _check_meta_vaults(meta_vault_addresses: list[ChecksumAddress]) -> None:
    meta_vaults = await graph_get_vaults(is_meta_vault=True)

    for vault in meta_vault_addresses:
        if vault not in meta_vaults:
            raise ClickException(f'Vault {vault} is not a meta vault')
