import logging

from eth_typing import HexStr
from web3 import Web3

from src.common.clients import execution_client
from src.common.contracts import get_gno_vault_contract, vault_contract
from src.common.typings import HarvestParams
from src.common.utils import format_error
from src.config.networks import GNO_NETWORKS
from src.config.settings import settings

logger = logging.getLogger(__name__)


async def submit_harvest_transaction(harvest_params: HarvestParams) -> HexStr | None:
    logger.info('Submitting harvest transaction...')
    tx_hash = None

    if settings.network in GNO_NETWORKS:
        tx_hash = await _gno_submit_harvest_transaction(harvest_params)

    if not tx_hash:
        tx_hash = await _eth_submit_harvest_transaction(harvest_params)

    if not tx_hash:
        return None

    logger.info('Waiting for transaction %s confirmation', tx_hash)
    tx_receipt = await execution_client.eth.wait_for_transaction_receipt(
        tx_hash, timeout=settings.execution_transaction_timeout
    )
    if not tx_receipt['status']:
        logger.error('Harvest transaction failed')
        return None

    return tx_hash


async def _eth_submit_harvest_transaction(harvest_params: HarvestParams) -> HexStr | None:
    logger.info('Submitting harvest transaction...')
    try:
        tx = await vault_contract.functions.updateState(
            (
                harvest_params.rewards_root,
                harvest_params.reward,
                harvest_params.unlocked_mev_reward,
                harvest_params.proof,
            )
        ).transact()
    except Exception as e:
        logger.error('Failed to harvest: %s', format_error(e))
        if settings.verbose:
            logger.exception(e)
        return None

    tx_hash = Web3.to_hex(tx)
    return tx_hash


async def _gno_submit_harvest_transaction(harvest_params: HarvestParams) -> HexStr | None:
    gno_vault_contract = get_gno_vault_contract()

    update_state_args = [
        (
            harvest_params.rewards_root,
            harvest_params.reward,
            harvest_params.unlocked_mev_reward,
            harvest_params.proof,
        )
    ]

    update_state_call = gno_vault_contract.encode_abi(fn_name='updateState', args=update_state_args)
    swap_xdai_call = gno_vault_contract.encode_abi(fn_name='swapXdaiToGno', args=[])

    try:
        tx = await gno_vault_contract.functions.multicall(
            [update_state_call, swap_xdai_call]
        ).transact()
    except Exception as e:
        logger.error('Failed to harvest and swap: %s', format_error(e))
        if settings.verbose:
            logger.exception(e)
        return None

    tx_hash = Web3.to_hex(tx)
    return tx_hash
