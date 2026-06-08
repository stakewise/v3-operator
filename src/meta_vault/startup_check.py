import logging

from click import ClickException
from eth_typing import ChecksumAddress

from src.common.clients import execution_client
from src.common.execution import check_wallet_balance
from src.common.startup_check import (
    check_execution_nodes_network,
    check_operator_version,
    wait_for_execution_node,
    wait_for_graph_node_sync_to_chain_head,
)
from src.common.wallet import wallet
from src.config.settings import settings
from src.meta_vault.graph import graph_get_vaults
from src.reward_splitter.graph import graph_get_reward_splitters

logger = logging.getLogger(__name__)


async def startup_checks(meta_vault_addresses: list[ChecksumAddress]) -> None:
    logger.info('Checking for newer operator version...')
    await check_operator_version()

    logger.info('Checking connection to execution nodes...')
    await wait_for_execution_node()

    logger.info('Checking execution nodes network...')
    await check_execution_nodes_network()

    logger.info('Checking graph nodes...')
    await wait_for_graph_node_sync_to_chain_head()

    logger.info('Checking meta vault addresses %s...', ', '.join(meta_vault_addresses))
    await _check_meta_vaults(meta_vault_addresses)

    if settings.claim_fee_splitter:
        logger.info('Checking fee splitters...')
        await _check_fee_splitters(meta_vault_addresses)

    logger.info('Checking wallet balance %s...', wallet.address)
    await check_wallet_balance()


async def _check_meta_vaults(meta_vault_addresses: list[ChecksumAddress]) -> None:
    meta_vaults = await graph_get_vaults(is_meta_vault=True)

    for vault in meta_vault_addresses:
        if vault not in meta_vaults:
            raise ClickException(f'Vault {vault} is not a meta vault')


async def _check_fee_splitters(meta_vault_addresses: list[ChecksumAddress]) -> None:
    """
    Warn when no fee splitter with the operator wallet as the configured claimer
    is found for a meta vault, since nothing would be claimed for it.
    """
    block = await execution_client.eth.get_block('finalized')

    for vault in meta_vault_addresses:
        reward_splitters = await graph_get_reward_splitters(
            block_number=block['number'], claimer=wallet.account.address, vault=vault
        )
        if not reward_splitters:
            logger.warning(
                'No fee splitters found for meta vault %s with the operator wallet %s as claimer',
                vault,
                wallet.address,
            )
