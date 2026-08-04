from unittest.mock import AsyncMock, Mock, patch

import pytest
from eth_typing import HexStr
from eth_utils import add_0x_prefix
from sw_utils.tests import faker
from web3.types import Gwei

from src.common.tests.utils import ether_to_gwei
from src.config.settings import settings
from src.validators.exceptions import EmptyRelayerResponseException
from src.validators.relayer import RelayerClient, _parse_validator
from src.validators.tasks import register_new_validators


@pytest.mark.usefixtures('fake_settings')
class TestRegisterValidators:
    """Tests for RelayerClient.register_validators"""

    @pytest.mark.parametrize('raw_amount', ['32000000000', 32000000000])
    async def test_amount_is_coerced_to_gwei(self, raw_amount):
        """Validator amount is coerced to int Gwei regardless of the relayer's JSON type."""
        public_key = faker.validator_public_key()
        relayer_response = {
            'validators': [{'public_key': public_key, 'amount': raw_amount}],
            'validators_manager_signature': None,
        }
        relayer = RelayerClient()
        with (
            patch(
                'src.validators.relayer.get_validators_start_index',
                new_callable=AsyncMock,
                return_value=0,
            ),
            patch.object(
                RelayerClient,
                '_register_validators',
                new_callable=AsyncMock,
                return_value=relayer_response,
            ),
        ):
            result = await relayer.register_validators(amounts=[Gwei(32000000000)])

        assert len(result.validators) == 1
        assert result.validators[0].amount == 32000000000
        assert isinstance(result.validators[0].amount, int)


@pytest.mark.usefixtures('fake_settings')
class TestFundValidators:
    """Tests for RelayerClient.fund_validators"""

    @pytest.mark.parametrize('signature_value', [None, ''])
    async def test_raises_when_signature_missing(self, signature_value):
        """A missing or empty signature means the relayer isn't ready yet."""
        relayer = RelayerClient()
        public_key = faker.validator_public_key()
        relayer_response = {'validators_manager_signature': signature_value}
        with patch.object(
            RelayerClient,
            '_fund_validators',
            new_callable=AsyncMock,
            return_value=relayer_response,
        ):
            with pytest.raises(EmptyRelayerResponseException):
                await relayer.fund_validators(
                    validator_fundings=[(public_key, Gwei(1_000_000_000))]
                )

    async def test_returns_signature_when_present(self):
        relayer = RelayerClient()
        public_key = faker.validator_public_key()
        signature = 'ab' * 32
        relayer_response = {'validators_manager_signature': signature}
        with patch.object(
            RelayerClient,
            '_fund_validators',
            new_callable=AsyncMock,
            return_value=relayer_response,
        ):
            result = await relayer.fund_validators(
                validator_fundings=[(public_key, Gwei(1_000_000_000))]
            )

        assert result.validators_manager_signature == add_0x_prefix(HexStr(signature))


class TestParseValidator:
    """Tests for _parse_validator boundary behavior on malformed relayer entries."""

    def test_missing_amount_raises_key_error(self):
        with pytest.raises(KeyError):
            _parse_validator({'public_key': faker.validator_public_key()})

    def test_missing_public_key_raises_key_error(self):
        with pytest.raises(KeyError):
            _parse_validator({'amount': '32000000000'})


@pytest.mark.usefixtures('fake_settings')
class TestRegisterNewValidatorsMalformedResponse:
    """register_new_validators must treat a malformed relayer response as 'not ready yet'."""

    @pytest.mark.parametrize('error', [TypeError('bad amount'), KeyError('amount')])
    async def test_returns_none_and_skips_oracle_polling(self, error):
        vault_assets = ether_to_gwei(32)
        relayer = Mock(spec=RelayerClient)
        relayer.register_validators = AsyncMock(side_effect=error)
        protocol_config = Mock(validators_approval_batch_limit=10)

        with (
            patch.object(settings, 'relayer_endpoint', 'http://relayer'),
            patch(
                'src.validators.tasks.get_protocol_config',
                new_callable=AsyncMock,
                return_value=protocol_config,
            ),
            patch(
                'src.validators.tasks.validators_registry_contract.get_registry_root',
                new_callable=AsyncMock,
                return_value=HexStr('0x' + '00' * 32),
            ),
            patch(
                'src.validators.tasks.check_gas_price',
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch(
                'src.validators.tasks.poll_validation_approval', new_callable=AsyncMock
            ) as mock_poll,
        ):
            result = await register_new_validators(
                vault_assets=vault_assets,
                harvest_params=None,
                keystore=None,
                relayer=relayer,
            )

        assert result is None
        mock_poll.assert_not_called()
