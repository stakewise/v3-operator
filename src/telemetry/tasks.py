import logging
import time
from urllib.parse import urljoin

import aiohttp
from aiohttp import ClientTimeout
from eth_account.messages import encode_defunct
from eth_typing import ChecksumAddress, HexStr
from sw_utils import InterruptHandler
from web3 import Web3

import src
from src.common.clients import OPERATOR_USER_AGENT
from src.common.tasks import BaseTask
from src.common.wallet import wallet
from src.config.settings import TELEMETRY_INTERVAL, settings

logger = logging.getLogger(__name__)

TELEMETRY_ENDPOINT = 'api/operator-telemetry'
TELEMETRY_TIMEOUT = 30

MESSAGE_PREFIX = 'operator'
MESSAGE_SEPARATOR = '_'


def build_telemetry_message(vault: ChecksumAddress, operator_version: str, timestamp: int) -> str:
    """
    Builds the message signed by the vault validators manager.
    Must match the message derived by the StakeWise backend.
    """
    return MESSAGE_SEPARATOR.join([MESSAGE_PREFIX, str(timestamp), vault, operator_version])


class TelemetryTask(BaseTask):
    """Reports the operator version to the StakeWise backend."""

    def __init__(self) -> None:
        self.last_report_timestamp: float | None = None

    async def process_block(self, interrupt_handler: InterruptHandler) -> None:
        current_timestamp = time.time()
        if (
            self.last_report_timestamp is not None
            and current_timestamp - self.last_report_timestamp < TELEMETRY_INTERVAL
        ):
            return

        # Update the timestamp before the attempt so that failures
        # are retried after the interval passes, not on the next block.
        self.last_report_timestamp = current_timestamp

        try:
            await self.report_operator_version()
        except Exception as e:
            logger.warning('Failed to report operator version: %s', e)

    async def report_operator_version(self) -> None:
        timestamp = int(time.time())
        operator_version = src.__version__
        message = build_telemetry_message(
            vault=settings.vault, operator_version=operator_version, timestamp=timestamp
        )
        signature = self._sign_message(message)

        base_url = settings.network_config.STAKEWISE_REST_API_URL
        url = urljoin(base_url + '/', TELEMETRY_ENDPOINT)
        payload = {
            'vault': settings.vault,
            'operator_version': operator_version,
            'timestamp': timestamp,
            'signature': signature,
        }

        async with aiohttp.ClientSession(
            timeout=ClientTimeout(TELEMETRY_TIMEOUT),
            headers={'User-Agent': OPERATOR_USER_AGENT},
        ) as session:
            resp = await session.post(url, json=payload)
            if 400 <= resp.status < 500:
                logger.debug('Telemetry response: %s', await resp.read())
            resp.raise_for_status()

        logger.debug('Reported operator version %s', operator_version)

    def _sign_message(self, message: str) -> HexStr:
        signed_msg = wallet.sign_message(encode_defunct(text=message))
        return Web3.to_hex(signed_msg.signature)
