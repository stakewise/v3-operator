from contextlib import contextmanager
from unittest.mock import AsyncMock, patch

import pytest
from eth_typing import HexStr
from sw_utils import ValidatorStatus
from sw_utils.tests import faker
from web3.types import Gwei

from src.common.tests.utils import ether_to_gwei
from src.common.typings import ValidatorType
from src.config.networks import HOODI
from src.config.settings import MIN_ACTIVATION_BALANCE_GWEI, settings
from src.validators.exceptions import FundingException
from src.validators.tasks import (
    ValidatorRegistrationSubtask,
    get_deposits_amounts,
    get_funding_amounts,
)
from src.validators.typings import VaultValidator


@pytest.mark.usefixtures('fake_settings')
def test_get_deposits_amounts():
    assert get_deposits_amounts(0, ValidatorType.V1) == []
    assert get_deposits_amounts(0, ValidatorType.V2) == []

    assert get_deposits_amounts(ether_to_gwei(32), ValidatorType.V1) == [
        MIN_ACTIVATION_BALANCE_GWEI
    ]
    assert get_deposits_amounts(ether_to_gwei(32), ValidatorType.V2) == [
        MIN_ACTIVATION_BALANCE_GWEI
    ]

    assert get_deposits_amounts(ether_to_gwei(33), ValidatorType.V1) == [
        MIN_ACTIVATION_BALANCE_GWEI,
    ]
    assert get_deposits_amounts(ether_to_gwei(33), ValidatorType.V2) == [ether_to_gwei(33)]

    assert get_deposits_amounts(ether_to_gwei(64), ValidatorType.V1) == [
        MIN_ACTIVATION_BALANCE_GWEI,
        MIN_ACTIVATION_BALANCE_GWEI,
    ]
    assert get_deposits_amounts(ether_to_gwei(64), ValidatorType.V2) == [ether_to_gwei(64)]

    assert get_deposits_amounts(ether_to_gwei(66), ValidatorType.V1) == [
        MIN_ACTIVATION_BALANCE_GWEI,
        MIN_ACTIVATION_BALANCE_GWEI,
    ]
    assert get_deposits_amounts(ether_to_gwei(66), ValidatorType.V2) == [ether_to_gwei(66)]

    assert (
        get_deposits_amounts(ether_to_gwei(2048), ValidatorType.V1)
        == [MIN_ACTIVATION_BALANCE_GWEI] * 64
    )
    assert get_deposits_amounts(settings.max_validator_balance_gwei, ValidatorType.V2) == [
        settings.max_validator_balance_gwei,
    ]
    assert get_deposits_amounts(ether_to_gwei(2048), ValidatorType.V2) == [
        settings.max_validator_balance_gwei,
        ether_to_gwei(2048) - settings.max_validator_balance_gwei,
    ]

    assert (
        get_deposits_amounts(ether_to_gwei(2050), ValidatorType.V1)
        == [MIN_ACTIVATION_BALANCE_GWEI] * 64
    )
    assert (
        get_deposits_amounts(ether_to_gwei(2081), ValidatorType.V1)
        == [MIN_ACTIVATION_BALANCE_GWEI] * 65
    )
    assert get_deposits_amounts(ether_to_gwei(2050), ValidatorType.V2) == [
        settings.max_validator_balance_gwei,
        ether_to_gwei(2050) - settings.max_validator_balance_gwei,
    ]

    assert get_deposits_amounts(ether_to_gwei(2081), ValidatorType.V2) == [
        settings.max_validator_balance_gwei,
        ether_to_gwei(2081) - settings.max_validator_balance_gwei,
    ]
    assert (
        get_deposits_amounts(ether_to_gwei(4096), ValidatorType.V1)
        == [MIN_ACTIVATION_BALANCE_GWEI] * 128
    )
    assert get_deposits_amounts(settings.max_validator_balance_gwei * 2, ValidatorType.V2) == [
        settings.max_validator_balance_gwei,
        settings.max_validator_balance_gwei,
    ]


def test_get_funding_amounts(data_dir):
    settings.set(vault=None, vault_dir=data_dir, network=HOODI)
    public_key_1 = faker.eth_address()
    public_key_2 = faker.eth_address()

    data = get_funding_amounts({public_key_1: ether_to_gwei(32)}, vault_assets=ether_to_gwei(1))
    assert data == {public_key_1: ether_to_gwei(1)}

    data = get_funding_amounts({public_key_1: ether_to_gwei(32)}, vault_assets=ether_to_gwei(100))
    assert data == {public_key_1: ether_to_gwei(100)}

    data = get_funding_amounts(
        {public_key_1: ether_to_gwei(32), public_key_2: ether_to_gwei(33)},
        vault_assets=ether_to_gwei(2100),
    )
    assert data == {
        public_key_2: ether_to_gwei(1912),
        public_key_1: ether_to_gwei(188),
    }

    data = get_funding_amounts(
        {public_key_1: ether_to_gwei(1934), public_key_2: ether_to_gwei(32)},
        vault_assets=ether_to_gwei(11.5),
    )
    assert data == {
        public_key_1: ether_to_gwei(11),
    }

    data = get_funding_amounts(
        {public_key_1: ether_to_gwei(32), public_key_2: ether_to_gwei(33)},
        vault_assets=ether_to_gwei(2100.5),
    )
    assert data == {
        public_key_2: ether_to_gwei(1912),
        public_key_1: ether_to_gwei(188.5),
    }


class TestProcessFunding:
    """Tests for ValidatorRegistrationSubtask.process_funding"""

    def setup_method(self):
        self.subtask = ValidatorRegistrationSubtask(keystore=None, relayer=None)

    @staticmethod
    @contextmanager
    def patch_compounding_validators_balances(return_value):
        with patch(
            'src.validators.tasks.fetch_compounding_validators_balances',
            new_callable=AsyncMock,
            return_value=return_value,
        ):
            yield

    @staticmethod
    @contextmanager
    def patch_is_funding_interval_passed(return_value):
        with patch(
            'src.validators.tasks._is_funding_interval_passed',
            new_callable=AsyncMock,
            return_value=return_value,
        ):
            yield

    @staticmethod
    @contextmanager
    def patch_fund_compounding_validators(return_value):
        with patch(
            'src.validators.tasks.fund_compounding_validators',
            new_callable=AsyncMock,
            return_value=return_value,
        ) as mock_fund:
            yield mock_fund

    @staticmethod
    @contextmanager
    def patch_get_latest_vault_v2_validator_public_keys(return_value=None):
        with patch(
            'src.validators.consensus.get_latest_vault_v2_validator_public_keys',
            new_callable=AsyncMock,
            return_value=return_value if return_value is not None else set(),
        ):
            yield

    @staticmethod
    @contextmanager
    def patch_settings(**kwargs):
        with patch.multiple(settings, create=True, **kwargs):
            yield

    @pytest.mark.usefixtures('fake_settings')
    async def test_no_compounding_validators(self):
        """Returns vault_assets unchanged when no compounding validators exist."""
        vault_assets = ether_to_gwei(100)
        with (
            self.patch_compounding_validators_balances({}),
            self.patch_fund_compounding_validators(None) as mock_fund,
        ):
            result = await self.subtask.process_funding(
                vault_assets=vault_assets, harvest_params=None
            )
        assert result == vault_assets
        mock_fund.assert_not_called()

    @pytest.mark.usefixtures('fake_settings')
    async def test_no_funding_needed(self):
        """Returns vault_assets unchanged when validators are already at max balance."""
        vault_assets = ether_to_gwei(100)
        pub_key = faker.validator_public_key()
        with (
            self.patch_compounding_validators_balances(
                {pub_key: settings.max_validator_balance_gwei}
            ),
            self.patch_fund_compounding_validators(None) as mock_fund,
        ):
            result = await self.subtask.process_funding(
                vault_assets=vault_assets, harvest_params=None
            )
        assert result == vault_assets
        mock_fund.assert_not_called()

    @pytest.mark.usefixtures('fake_settings')
    async def test_funding_interval_not_passed(self):
        """Raises FundingException when funding interval hasn't passed."""
        vault_assets = ether_to_gwei(100)
        pub_key = faker.validator_public_key()
        with (
            self.patch_compounding_validators_balances({pub_key: ether_to_gwei(32)}),
            self.patch_is_funding_interval_passed(False),
            self.patch_fund_compounding_validators(None) as mock_fund,
        ):
            with pytest.raises(FundingException, match='Funding interval has not passed yet'):
                await self.subtask.process_funding(vault_assets=vault_assets, harvest_params=None)
        mock_fund.assert_not_called()

    @pytest.mark.usefixtures('fake_settings')
    async def test_successful_funding_single_validator(self):
        """Funds a single validator and returns remaining vault assets."""
        vault_assets = ether_to_gwei(100)
        pub_key = faker.validator_public_key()
        tx_hash = HexStr('0xabc')

        with (
            self.patch_compounding_validators_balances({pub_key: ether_to_gwei(32)}),
            self.patch_is_funding_interval_passed(True),
            self.patch_fund_compounding_validators(tx_hash) as mock_fund,
        ):
            result = await self.subtask.process_funding(
                vault_assets=vault_assets, harvest_params=None
            )

        mock_fund.assert_called_once()
        call_kwargs = mock_fund.call_args[1]
        assert dict(call_kwargs['validator_fundings']) == {pub_key: vault_assets}
        assert result == Gwei(0)

    @pytest.mark.usefixtures('fake_settings')
    async def test_funding_tx_failed(self):
        """Raises FundingException when fund_compounding_validators returns None."""
        vault_assets = ether_to_gwei(100)
        pub_key = faker.validator_public_key()

        with (
            self.patch_compounding_validators_balances({pub_key: ether_to_gwei(32)}),
            self.patch_is_funding_interval_passed(True),
            self.patch_fund_compounding_validators(None),
        ):
            with pytest.raises(FundingException, match='Funding transaction failed'):
                await self.subtask.process_funding(vault_assets=vault_assets, harvest_params=None)

    @pytest.mark.usefixtures('fake_settings')
    async def test_funding_multiple_validators(self):
        """Funds multiple validators and correctly reduces vault assets."""
        pub_key_1 = faker.validator_public_key()
        pub_key_2 = faker.validator_public_key()
        vault_assets = ether_to_gwei(200)
        tx_hash = HexStr('0xabc')

        with (
            self.patch_settings(max_validator_balance_gwei=ether_to_gwei(64)),
            self.patch_compounding_validators_balances(
                {
                    pub_key_1: ether_to_gwei(32),
                    pub_key_2: ether_to_gwei(33),
                }
            ),
            self.patch_is_funding_interval_passed(True),
            self.patch_fund_compounding_validators(tx_hash) as mock_fund,
        ):
            result = await self.subtask.process_funding(
                vault_assets=vault_assets, harvest_params=None
            )

        # Both validators should be funded
        # max_balance=64, so capacity = 64 - balance for each
        mock_fund.assert_called_once()
        # max_balance=64, capacity = 64 - balance: 32 and 31
        assert dict(mock_fund.call_args[1]['validator_fundings']) == {
            pub_key_1: ether_to_gwei(32),
            pub_key_2: ether_to_gwei(31),
        }
        # 200 - 32 - 31 = 137
        assert result == ether_to_gwei(137)

    # Funding prioritizes highest balances first, so we test both cases:
    # exiting validator has lower balance (32) and higher balance (40)
    # to ensure it's excluded regardless of funding order.
    @pytest.mark.parametrize(
        'active_balance, exiting_balance',
        [(40, 32), (32, 40)],
    )
    async def test_fetch_compounding_filters_exiting_validators(
        self, vault_validator_crud, compounding_creds, active_balance, exiting_balance
    ):
        """fetch_compounding_validators_balances excludes exiting/exited validators."""
        pub_key_active = faker.validator_public_key()
        pub_key_exiting = faker.validator_public_key()

        vault_validator_crud.save_vault_validators(
            [
                VaultValidator(public_key=pub_key_active, block_number=1),
                VaultValidator(public_key=pub_key_exiting, block_number=2),
            ]
        )

        consensus_validators_data = [
            {
                'index': '1',
                'balance': str(ether_to_gwei(active_balance)),
                'validator': {
                    'pubkey': pub_key_active[2:],
                    'withdrawal_credentials': compounding_creds,
                    'activation_epoch': '0',
                },
                'status': ValidatorStatus.ACTIVE_ONGOING.value,
            },
            {
                'index': '2',
                'balance': str(ether_to_gwei(exiting_balance)),
                'validator': {
                    'pubkey': pub_key_exiting[2:],
                    'withdrawal_credentials': compounding_creds,
                    'activation_epoch': '0',
                },
                'status': ValidatorStatus.ACTIVE_EXITING.value,
            },
        ]

        mock_consensus = AsyncMock()
        mock_consensus.get_block.return_value = {'data': {'message': {'slot': '100'}}}
        mock_consensus.get_validators_by_ids.return_value = {'data': consensus_validators_data}
        mock_consensus.get_pending_deposits.return_value = []

        with (
            self.patch_get_latest_vault_v2_validator_public_keys(),
            patch('src.validators.consensus.consensus_client', mock_consensus),
            self.patch_is_funding_interval_passed(True),
            self.patch_fund_compounding_validators(HexStr('0xabc')) as mock_fund,
        ):

            vault_assets = ether_to_gwei(100)
            result = await self.subtask.process_funding(
                vault_assets=vault_assets, harvest_params=None
            )

        # Only active compounding validator should be funded, not the exiting one
        mock_fund.assert_called_once()
        assert dict(mock_fund.call_args[1]['validator_fundings']) == {
            pub_key_active: ether_to_gwei(100),
        }
        assert result == Gwei(0)

    async def test_fetch_compounding_includes_pending_deposits(
        self, vault_validator_crud, compounding_creds
    ):
        """Pending deposits reduce remaining capacity, causing overflow to second validator."""
        pub_key_1 = faker.validator_public_key()
        pub_key_2 = faker.validator_public_key()

        vault_validator_crud.save_vault_validators(
            [
                VaultValidator(public_key=pub_key_1, block_number=1),
                VaultValidator(public_key=pub_key_2, block_number=2),
            ]
        )

        # max_balance=64, balance=40, pending=10 → effective=50, capacity=14
        # vault_assets=30 > capacity=14, so 14 goes to pub_key_1
        # remaining 16 (>= min_deposit 10) goes to pub_key_2 (balance=32, capacity=32)
        consensus_balance_1 = ether_to_gwei(40)
        consensus_balance_2 = ether_to_gwei(32)
        pending_amount = ether_to_gwei(10)

        consensus_validators_data = [
            {
                'index': '1',
                'balance': str(consensus_balance_1),
                'validator': {
                    'pubkey': pub_key_1[2:],
                    'withdrawal_credentials': compounding_creds,
                    'activation_epoch': '0',
                },
                'status': ValidatorStatus.ACTIVE_ONGOING.value,
            },
            {
                'index': '2',
                'balance': str(consensus_balance_2),
                'validator': {
                    'pubkey': pub_key_2[2:],
                    'withdrawal_credentials': compounding_creds,
                    'activation_epoch': '0',
                },
                'status': ValidatorStatus.ACTIVE_ONGOING.value,
            },
        ]

        mock_consensus = AsyncMock()
        mock_consensus.get_block.return_value = {'data': {'message': {'slot': '100'}}}
        mock_consensus.get_validators_by_ids.return_value = {'data': consensus_validators_data}
        mock_consensus.get_pending_deposits.return_value = [
            {'pubkey': pub_key_1, 'amount': str(pending_amount)},
        ]

        with (
            self.patch_settings(max_validator_balance_gwei=ether_to_gwei(64)),
            self.patch_get_latest_vault_v2_validator_public_keys(),
            patch('src.validators.consensus.consensus_client', mock_consensus),
            self.patch_is_funding_interval_passed(True),
            self.patch_fund_compounding_validators(HexStr('0xabc')) as mock_fund,
        ):
            vault_assets = ether_to_gwei(30)
            result = await self.subtask.process_funding(
                vault_assets=vault_assets, harvest_params=None
            )

        mock_fund.assert_called_once()
        # pub_key_1: capacity = 64 - (40 + 10) = 14
        # pub_key_2: gets remaining 30 - 14 = 16
        assert dict(mock_fund.call_args[1]['validator_fundings']) == {
            pub_key_1: ether_to_gwei(14),
            pub_key_2: ether_to_gwei(16),
        }
        assert result == Gwei(0)

    async def test_fetch_compounding_excludes_non_compounding(
        self, vault_validator_crud, compounding_creds
    ):
        """Non-compounding (0x01) validator is excluded even when vault has excess assets."""
        pub_key_compounding = faker.validator_public_key()
        pub_key_non_compounding = faker.validator_public_key()
        non_compounding_creds = '0x01' + compounding_creds[4:]

        vault_validator_crud.save_vault_validators(
            [
                VaultValidator(public_key=pub_key_compounding, block_number=1),
                VaultValidator(public_key=pub_key_non_compounding, block_number=2),
            ]
        )

        # max_balance=64, compounding balance=40 → capacity=24
        # non-compounding balance=32 but should be excluded
        # vault_assets=40 overwhelms compounding capacity (24),
        # but remaining 16 must NOT go to the non-compounding validator
        consensus_validators_data = [
            {
                'index': '1',
                'balance': str(ether_to_gwei(40)),
                'validator': {
                    'pubkey': pub_key_compounding[2:],
                    'withdrawal_credentials': compounding_creds,
                    'activation_epoch': '0',
                },
                'status': ValidatorStatus.ACTIVE_ONGOING.value,
            },
            {
                'index': '2',
                'balance': str(ether_to_gwei(32)),
                'validator': {
                    'pubkey': pub_key_non_compounding[2:],
                    'withdrawal_credentials': non_compounding_creds,
                    'activation_epoch': '0',
                },
                'status': ValidatorStatus.ACTIVE_ONGOING.value,
            },
        ]

        mock_consensus = AsyncMock()
        mock_consensus.get_block.return_value = {'data': {'message': {'slot': '100'}}}
        mock_consensus.get_validators_by_ids.return_value = {'data': consensus_validators_data}
        mock_consensus.get_pending_deposits.return_value = []

        with (
            self.patch_settings(max_validator_balance_gwei=ether_to_gwei(64)),
            self.patch_get_latest_vault_v2_validator_public_keys(),
            patch('src.validators.consensus.consensus_client', mock_consensus),
            self.patch_is_funding_interval_passed(True),
            self.patch_fund_compounding_validators(HexStr('0xabc')) as mock_fund,
        ):
            vault_assets = ether_to_gwei(40)
            result = await self.subtask.process_funding(
                vault_assets=vault_assets, harvest_params=None
            )

        mock_fund.assert_called_once()
        # Only compounding validator funded, capped at capacity = 64 - 40 = 24
        assert dict(mock_fund.call_args[1]['validator_fundings']) == {
            pub_key_compounding: ether_to_gwei(24),
        }
        # 40 - 24 = 16
        assert result == ether_to_gwei(16)

    @pytest.mark.usefixtures('vault_validator_crud')
    async def test_fetch_compounding_includes_non_finalized_keys(self, compounding_creds):
        """fetch_compounding_validators_balances includes non-finalized V2 validator keys."""
        pub_key = faker.validator_public_key()

        # No vault validators in DB — key comes from non-finalized V2 events
        consensus_validators_data = [
            {
                'index': '1',
                'balance': str(ether_to_gwei(32)),
                'validator': {
                    'pubkey': pub_key[2:],
                    'withdrawal_credentials': compounding_creds,
                    'activation_epoch': '0',
                },
                'status': ValidatorStatus.ACTIVE_ONGOING.value,
            },
        ]

        mock_consensus = AsyncMock()
        mock_consensus.get_block.return_value = {'data': {'message': {'slot': '100'}}}
        mock_consensus.get_validators_by_ids.return_value = {'data': consensus_validators_data}
        mock_consensus.get_pending_deposits.return_value = []

        with (
            self.patch_get_latest_vault_v2_validator_public_keys({pub_key}),
            patch('src.validators.consensus.consensus_client', mock_consensus),
            self.patch_is_funding_interval_passed(True),
            self.patch_fund_compounding_validators(HexStr('0xabc')) as mock_fund,
        ):

            vault_assets = ether_to_gwei(100)
            result = await self.subtask.process_funding(
                vault_assets=vault_assets, harvest_params=None
            )

        mock_fund.assert_called_once()
        assert dict(mock_fund.call_args[1]['validator_fundings']) == {
            pub_key: ether_to_gwei(100),
        }
        assert result == Gwei(0)

    @pytest.mark.usefixtures('fake_settings')
    async def test_funding_batching(self):
        """3 validators are funded in 2 batches when VALIDATORS_FUNDING_BATCH_SIZE=2."""
        pub_key_1 = faker.validator_public_key()
        pub_key_2 = faker.validator_public_key()
        pub_key_3 = faker.validator_public_key()
        tx_hash = HexStr('0xabc')

        with (
            self.patch_settings(max_validator_balance_gwei=ether_to_gwei(64)),
            self.patch_compounding_validators_balances(
                {
                    pub_key_1: ether_to_gwei(32),
                    pub_key_2: ether_to_gwei(33),
                    pub_key_3: ether_to_gwei(34),
                }
            ),
            self.patch_is_funding_interval_passed(True),
            self.patch_fund_compounding_validators(tx_hash) as mock_fund,
            patch('src.validators.tasks.VALIDATORS_FUNDING_BATCH_SIZE', 2),
        ):
            vault_assets = ether_to_gwei(100)
            result = await self.subtask.process_funding(
                vault_assets=vault_assets, harvest_params=None
            )

        # 3 validators split into 2 batches: [2, 1]
        assert mock_fund.call_count == 2

        batch_1 = dict(mock_fund.call_args_list[0][1]['validator_fundings'])
        batch_2 = dict(mock_fund.call_args_list[1][1]['validator_fundings'])
        assert len(batch_1) == 2
        assert len(batch_2) == 1

        # Funding sorts by balance descending: pub_key_3 (34), pub_key_2 (33), pub_key_1 (32)
        # max_balance=64, so capacity = 64 - balance: 30, 31, 32
        assert batch_1 == {pub_key_3: ether_to_gwei(30), pub_key_2: ether_to_gwei(31)}
        assert batch_2 == {pub_key_1: ether_to_gwei(32)}
        # 100 - 30 - 31 - 32 = 7
        assert result == ether_to_gwei(7)
