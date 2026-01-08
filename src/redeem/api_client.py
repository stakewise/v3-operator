import aiohttp
from eth_typing import ChecksumAddress
from sw_utils.common import urljoin
from web3 import Web3
from web3.types import Wei

from src.config.settings import settings

API_ENDPOINT = 'https://api.rabby.io/'
DEFAULT_USER_AGENT = (
    'Mozilla/5.0 (X11; Linux x86_64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'
)


class APIClient:

    base_url = API_ENDPOINT

    async def get_protocols_locked_locked_os_token(self, address: ChecksumAddress) -> Wei:
        url = urljoin(self.base_url, 'v1/user/complex_protocol_list')
        params = {
            'id': address,
        }

        protocol_data = []
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url=url,
                params=params,
                headers={'user-agent:': DEFAULT_USER_AGENT},
            ) as response:
                response.raise_for_status()
                protocol_data = await response.json()

        total_locked_oseth = Wei(0)
        for protocol in protocol_data:
            if protocol['id'] == 'stakewise':
                continue
            portfolio_item_list = protocol.get('portfolio_item_list', [])
            for item in portfolio_item_list:
                for assets in item.get('asset_token_list', []):
                    if not Web3.is_address(assets['id']):
                        continue
                    if (
                        Web3.to_checksum_address(assets['id'])
                        == settings.network_config.OS_TOKEN_CONTRACT_ADDRESS
                    ):
                        total_locked_oseth = Wei(
                            total_locked_oseth + Web3.to_wei(float(assets['amount']), 'ether')
                        )
        return total_locked_oseth
