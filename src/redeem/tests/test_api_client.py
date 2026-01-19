import json
from unittest.mock import patch

import pytest
from web3 import Web3
from web3.types import Wei

from src.config.settings import settings
from src.redeem.api_client import APIClient


class TestAPIClient:
    @pytest.mark.usefixtures('fake_settings')
    async def test_zero_when_no_protocol_data(self):
        client = APIClient()
        with patch('src.redeem.api_client.APIClient._fetch_json', return_value=[]):
            result = await client.get_protocols_locked_os_token(
                Web3.to_checksum_address('0x1234567890abcdef1234567890abcdef12345678')
            )
        assert result == Wei(0)

    @pytest.mark.usefixtures('fake_settings')
    async def test_excludes_stakewise_protocol_from_total(self):
        mock_protocol_data = [
            {
                'id': 'stakewise',
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
                'portfolio_item_list': [
                    {
                        'detail': {
                            'supply_token_list': [
                                {
                                    'id': settings.network_config.OS_TOKEN_CONTRACT_ADDRESS,
                                    'chain': 'eth',
                                    'amount': '5',
                                }
                            ]
                        }
                    }
                ],
            },
        ]
        with patch('src.redeem.api_client.APIClient._fetch_json', return_value=mock_protocol_data):
            client = APIClient()
            result = await client.get_protocols_locked_os_token(
                Web3.to_checksum_address('0x1234567890abcdef1234567890abcdef12345678')
            )
        assert result == Wei(Web3.to_wei(5, 'ether'))

    @pytest.mark.usefixtures('fake_settings')
    async def test_real_data(self):
        with open('src/redeem/tests/api_samples/protocols.json', 'r') as f:
            mock_protocol_data = json.load(f)
        settings.network_config.OS_TOKEN_CONTRACT_ADDRESS = (
            '0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38'
        )
        settings.network_config.OS_TOKEN_ARBITRUM_CONTRACT_ADDRESS = (
            '0xf7d4e7273E5015C96728A6b02f31C505eE184603'
        )
        with patch('src.redeem.api_client.APIClient._fetch_json', return_value=mock_protocol_data):
            client = APIClient()
            result = await client.get_protocols_locked_os_token(
                Web3.to_checksum_address('0x1234567890abcdef1234567890abcdef12345678')
            )
        assert result == Wei(5810497440414831)

    @pytest.mark.usefixtures('fake_settings')
    async def test_real_data_with_boost(self):
        with open('src/redeem/tests/api_samples/with_boost.json', 'r') as f:
            mock_protocol_data = json.load(f)
        settings.network_config.OS_TOKEN_CONTRACT_ADDRESS = (
            '0xf1C9acDc66974dFB6dEcB12aA385b9cD01190E38'
        )
        settings.network_config.OS_TOKEN_ARBITRUM_CONTRACT_ADDRESS = (
            '0xf7d4e7273E5015C96728A6b02f31C505eE184603'
        )
        with patch('src.redeem.api_client.APIClient._fetch_json', return_value=mock_protocol_data):
            client = APIClient()
            result = await client.get_protocols_locked_os_token(
                Web3.to_checksum_address('0x1234567890abcdef1234567890abcdef12345678')
            )
        assert result == Wei(0)
