import logging

from eth_typing import HexStr
from web3 import Web3
from web3.exceptions import ContractCustomError

from src.common.contracts import VaultContract
from src.common.transaction import tx_manager
from src.common.typings import HarvestParams
from src.config.settings import settings

logger = logging.getLogger(__name__)


async def submit_harvest_transaction(harvest_params: HarvestParams) -> HexStr | None:
    vault_contract = VaultContract(settings.vault)
    try:
        tx_function = vault_contract.functions.updateState(
            (
                harvest_params.rewards_root,
                harvest_params.reward,
                harvest_params.unlocked_mev_reward,
                harvest_params.proof,
            )
        )
        tx_receipt = await tx_manager.transact(tx_function)
    except ContractCustomError as e:
        reason = vault_contract.decode_custom_error(str(e.data)) or e.data
        logger.error('Failed to harvest: execution reverted with %s', reason)
        if settings.verbose:
            logger.exception(e)
        return None

    if tx_receipt is None:
        logger.error('Harvest transaction failed')
        return None

    return Web3.to_hex(tx_receipt['transactionHash'])
