import aiohttp
from eth_typing import ChecksumAddress
from sw_utils.common import urljoin
from web3 import Web3
from web3.types import Wei

from src.config.networks import GNOSIS, MAINNET, ZERO_CHECKSUM_ADDRESS
from src.config.settings import settings

RABBY_API_ENDPOINT = 'https://api.rabby.io/'
DEBANK_API_ENDPOINT = 'https://pro-openapi.debank.com/'
RABBY_API_SOURCE = 'rabby'
DEBANK_API_SOURCE = 'debank'
API_SOURCES = {
    RABBY_API_SOURCE: RABBY_API_ENDPOINT,
    DEBANK_API_SOURCE: DEBANK_API_ENDPOINT,
}
DEFAULT_USER_AGENT = (
    'Mozilla/5.0 (X11; Linux x86_64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'
)
API_SUPPORTED_CHAINS = {
    MAINNET: {'eth', 'arb'},
    GNOSIS: {'xdai'},
}
API_SLEEP_TIMEOUT = 1
STAKEWISE_DEBANK_PROTOCOL_IDS = ['stakewise', 'xdai_stakewise']


class APIClient:

    def __init__(
        self, api_source: str = RABBY_API_SOURCE, api_access_key: str | None = None
    ) -> None:
        self.base_url = API_SOURCES[api_source]
        self.api_access_key = api_access_key

    async def get_protocols_locked_os_token(self, address: ChecksumAddress) -> Wei:
        if settings.network not in API_SUPPORTED_CHAINS:
            raise ValueError(f'Unsupported network for Rabby API Client: {settings.network}')

        url = urljoin(self.base_url, 'v1/user/complex_protocol_list')
        params = {
            'id': address,
        }

        protocol_data = await self._fetch_json(url, params=params)
        total_locked_os_token = Wei(0)
        for protocol in protocol_data:
            if protocol['chain'] not in API_SUPPORTED_CHAINS[settings.network]:
                continue
            # boosted OsEth handled via graph separately
            if protocol['id'] in STAKEWISE_DEBANK_PROTOCOL_IDS:
                continue
            for portfolio_item in protocol.get('portfolio_item_list', []):
                supply_token_list = portfolio_item.get('detail', {}).get('supply_token_list', [])
                for supply_token in supply_token_list:
                    if supply_token['chain'] not in API_SUPPORTED_CHAINS[settings.network]:
                        continue
                    if not Web3.is_address(supply_token['id']):
                        continue
                    if self._is_os_token(Web3.to_checksum_address(supply_token['id'])):
                        total_locked_os_token = Wei(
                            total_locked_os_token + Web3.to_wei(supply_token['amount'], 'ether')
                        )

        return total_locked_os_token

    async def _fetch_json(self, url: str, params: dict | None = None) -> dict | list:
        headers: dict[str, str] = {'user-agent': DEFAULT_USER_AGENT}
        if self.api_access_key:
            headers['AccessKey'] = self.api_access_key
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url=url,
                params=params,
                headers=headers,
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
