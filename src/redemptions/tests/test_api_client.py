import json
from unittest.mock import patch

import pytest
from web3 import Web3
from web3.types import Wei

from src.config.networks import HOODI, MAINNET
from src.config.settings import settings
from src.redemptions.api_client import API_SLEEP_TIMEOUT, RABBY_API_SOURCE, APIClient
from src.redemptions.typings import ApiConfig

DEFAULT_API_CONFIG = ApiConfig(source=RABBY_API_SOURCE, sleep_timeout=API_SLEEP_TIMEOUT)


class TestAPIClient:
    @pytest.mark.usefixtures('fake_settings')
    async def test_zero_when_no_protocol_data(self):
        with patch.object(settings, 'network', MAINNET), patch(
            'src.redemptions.api_client.APIClient._fetch_json', return_value=[]
        ):
            client = APIClient(DEFAULT_API_CONFIG)
            result = await client.get_protocols_locked_os_token(
                Web3.to_checksum_address('0x1234567890abcdef1234567890abcdef12345678')
            )
        assert result == Wei(0)

    @pytest.mark.usefixtures('fake_settings')
    async def test_for_network_returns_none_on_unsupported_network(self):
        with patch.object(settings, 'network', HOODI):
            client = APIClient.for_network(DEFAULT_API_CONFIG)
        assert client is None

    @pytest.mark.usefixtures('fake_settings')
    async def test_for_network_returns_instance_on_supported_network(self):
        with patch.object(settings, 'network', MAINNET):
            client = APIClient.for_network(DEFAULT_API_CONFIG)
        assert isinstance(client, APIClient)

    @pytest.mark.usefixtures('fake_settings')
    async def test_excludes_stakewise_protocol_from_total(self):
        mock_protocol_data = [
            {
                'id': 'stakewise',
                'chain': 'eth',
                'portfolio_item_list': [
                    {
                        'detail': {
                            'supply_token_list': [
                                {
                                    'id': '0x1234567890abcdef1234567890abcdef12345678',
                                    'chain': 'eth',
                                    'amount': '57',
                                }
                            ]
                        }
                    }
                ],
            },
            {
                'id': 'other',
                'chain': 'eth',
                'portfolio_item_list': [
                    {
                        'detail': {
                            'supply_token_list': [
                                {
                                    'id': '0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38',
                                    'chain': 'eth',
                                    'amount': '5',
                                }
                            ]
                        }
                    }
                ],
            },
            {
                'id': 'other',
                'chain': 'xdai',
                'portfolio_item_list': [
                    {
                        'detail': {
                            'supply_token_list': [
                                {
                                    'id': '0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38',
                                    'chain': 'xdai',
                                    'amount': '3',
                                }
                            ]
                        }
                    }
                ],
            },
        ]
        with patch.object(settings, 'network', MAINNET), patch(
            'src.redemptions.api_client.APIClient._fetch_json', return_value=mock_protocol_data
        ), patch.object(
            settings.network_config,
            'OS_TOKEN_CONTRACT_ADDRESS',
            '0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38',
        ):
            client = APIClient(DEFAULT_API_CONFIG)
            result = await client.get_protocols_locked_os_token(
                Web3.to_checksum_address('0x1234567890abcdef1234567890abcdef12345678')
            )
        assert result == Wei(Web3.to_wei(5, 'ether'))

    @pytest.mark.usefixtures('fake_settings')
    async def test_real_data(self):
        with open('src/redemptions/tests/api_samples/protocols.json', 'r') as f:
            mock_protocol_data = json.load(f)
        with patch.object(settings, 'network', MAINNET), patch(
            'src.redemptions.api_client.APIClient._fetch_json', return_value=mock_protocol_data
        ), patch.object(
            settings.network_config,
            'OS_TOKEN_CONTRACT_ADDRESS',
            '0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38',
        ):
            client = APIClient(DEFAULT_API_CONFIG)
            result = await client.get_protocols_locked_os_token(
                Web3.to_checksum_address('0x1234567890abcdef1234567890abcdef12345678')
            )
        assert result == Wei(4908766246664556)

    @pytest.mark.usefixtures('fake_settings')
    async def test_real_data_with_boost(self):
        with open('src/redemptions/tests/api_samples/with_boost.json', 'r') as f:
            mock_protocol_data = json.load(f)
        with patch.object(settings, 'network', MAINNET), patch(
            'src.redemptions.api_client.APIClient._fetch_json', return_value=mock_protocol_data
        ), patch.object(
            settings.network_config,
            'OS_TOKEN_CONTRACT_ADDRESS',
            '0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38',
        ):
            client = APIClient(DEFAULT_API_CONFIG)
            result = await client.get_protocols_locked_os_token(
                Web3.to_checksum_address('0x1234567890abcdef1234567890abcdef12345678')
            )
        assert result == Wei(0)
