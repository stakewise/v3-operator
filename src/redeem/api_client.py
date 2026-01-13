import aiohttp
from eth_typing import ChecksumAddress
from sw_utils.common import urljoin
from web3 import Web3
from web3.types import Wei

from src.config.networks import ZERO_CHECKSUM_ADDRESS
from src.config.settings import settings

API_ENDPOINT = 'https://api.rabby.io/'
DEFAULT_USER_AGENT = (
    'Mozilla/5.0 (X11; Linux x86_64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'
)
SUPPORTED_CHAINS = {'eth', 'arb'}
API_SLEEP_TIMEOUT = 1


class APIClient:

    base_url = API_ENDPOINT

    async def get_protocols_locked_os_token(self, address: ChecksumAddress) -> Wei:
        url = urljoin(self.base_url, 'v1/user/complex_protocol_list')
        params = {
            'id': address,
        }

        protocol_data = await self._fetch_json(url, params=params)
        total_locked_oseth = Wei(0)
        for protocol in protocol_data:
            # boosted OsEth handled via graph separately
            if protocol['id'] in ['stakewise', 'xdai_stakewise']:
                continue
            for portfolio_item in protocol.get('portfolio_item_list', []):
                supply_token_list = portfolio_item.get('detail', {}).get('supply_token_list', [])
                for supply_token in supply_token_list:
                    if supply_token['chain'] not in SUPPORTED_CHAINS:
                        continue
                    if not Web3.is_address(supply_token['id']):
                        continue
                    if self._is_os_token(Web3.to_checksum_address(supply_token['id'])):
                        total_locked_oseth = Wei(
                            total_locked_oseth + Web3.to_wei(float(supply_token['amount']), 'ether')
                        )

        return total_locked_oseth

    async def _fetch_json(self, url: str, params: dict | None = None) -> dict | list:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url=url,
                params=params,
                headers={'user-agent': DEFAULT_USER_AGENT},
            ) as response:
                response.raise_for_status()
                return await response.json()

    def _is_os_token(self, token_address: ChecksumAddress) -> bool:
        if token_address == ZERO_CHECKSUM_ADDRESS:
            return False
        return token_address in [
            settings.network_config.OS_TOKEN_CONTRACT_ADDRESS,
            settings.network_config.OS_TOKEN_ARBITRUM_CONTRACT_ADDRESS,
        ]
