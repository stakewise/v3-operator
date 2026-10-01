from unittest.mock import AsyncMock, patch

import pytest
from sw_utils import ValidatorStatus
from sw_utils.tests import faker

from src.common.consolidations import get_pending_consolidations
from src.common.tests.factories import create_chain_head
from src.common.typings import PendingConsolidation
from src.config.settings import settings
from src.validators.tests.factories import create_consensus_validator


@pytest.mark.usefixtures('fake_settings')
class TestGetPendingConsolidations:
    """CL-queue entries come from `consensus_client.get_pending_consolidations`;
    EL-queue entries come from `get_execution_consolidations`. Both are mocked so no
    beacon/storage reads happen."""

    async def test_cl_queue_unresolved_target_does_not_raise(self):
        """A vault-registered source whose target isn't in `consensus_validators` yet
        (local DB indexing race) must not raise -- the entry is kept, with both indexes,
        so the source stays excluded from exit/partial selection elsewhere."""
        chain_head = create_chain_head()
        source_validator = create_consensus_validator(
            index=10, status=ValidatorStatus.ACTIVE_ONGOING, activation_epoch=1
        )

        mock_consensus = AsyncMock()
        mock_consensus.get_pending_consolidations.return_value = [
            {'source_index': '10', 'target_index': '99'}
        ]

        with patch('src.common.consolidations.consensus_client', mock_consensus), patch(
            'src.common.consolidations.get_execution_consolidations',
            AsyncMock(return_value=[]),
        ):
            result = await get_pending_consolidations(chain_head, [source_validator])

        assert result == [PendingConsolidation(source_index=10, target_index=99)]

    async def test_cl_queue_vault_source_and_target_included(self):
        chain_head = create_chain_head()
        source_validator = create_consensus_validator(
            index=10, status=ValidatorStatus.ACTIVE_ONGOING, activation_epoch=1
        )
        target_validator = create_consensus_validator(
            index=20, status=ValidatorStatus.ACTIVE_ONGOING, activation_epoch=1
        )

        mock_consensus = AsyncMock()
        mock_consensus.get_pending_consolidations.return_value = [
            {'source_index': '10', 'target_index': '20'}
        ]

        with patch('src.common.consolidations.consensus_client', mock_consensus), patch(
            'src.common.consolidations.get_execution_consolidations',
            AsyncMock(return_value=[]),
        ):
            result = await get_pending_consolidations(
                chain_head, [source_validator, target_validator]
            )

        assert result == [PendingConsolidation(source_index=10, target_index=20)]

    async def test_cl_queue_both_non_vault_skipped(self):
        chain_head = create_chain_head()

        mock_consensus = AsyncMock()
        mock_consensus.get_pending_consolidations.return_value = [
            {'source_index': '10', 'target_index': '20'}
        ]

        with patch('src.common.consolidations.consensus_client', mock_consensus), patch(
            'src.common.consolidations.get_execution_consolidations',
            AsyncMock(return_value=[]),
        ):
            result = await get_pending_consolidations(chain_head, [])

        assert result == []

    async def test_el_queue_vault_source_address_appended(self):
        chain_head = create_chain_head()
        source_validator = create_consensus_validator(
            index=1,
            public_key='0xsource',
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=1,
        )
        target_validator = create_consensus_validator(
            index=2,
            public_key='0xtarget',
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=1,
        )

        mock_consensus = AsyncMock()
        mock_consensus.get_pending_consolidations.return_value = []
        execution_consolidations = [
            {
                'source_address': settings.vault,
                'source_pubkey': '0xsource',
                'target_pubkey': '0xtarget',
            }
        ]

        with patch('src.common.consolidations.consensus_client', mock_consensus), patch(
            'src.common.consolidations.get_execution_consolidations',
            AsyncMock(return_value=execution_consolidations),
        ):
            result = await get_pending_consolidations(
                chain_head, [source_validator, target_validator]
            )

        assert result == [PendingConsolidation(source_index=1, target_index=2)]

    async def test_el_queue_wrong_source_address_skipped(self):
        chain_head = create_chain_head()
        source_validator = create_consensus_validator(
            index=1,
            public_key='0xsource',
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=1,
        )
        target_validator = create_consensus_validator(
            index=2,
            public_key='0xtarget',
            status=ValidatorStatus.ACTIVE_ONGOING,
            activation_epoch=1,
        )

        mock_consensus = AsyncMock()
        mock_consensus.get_pending_consolidations.return_value = []
        execution_consolidations = [
            {
                'source_address': faker.eth_address(),
                'source_pubkey': '0xsource',
                'target_pubkey': '0xtarget',
            }
        ]

        with patch('src.common.consolidations.consensus_client', mock_consensus), patch(
            'src.common.consolidations.get_execution_consolidations',
            AsyncMock(return_value=execution_consolidations),
        ):
            result = await get_pending_consolidations(
                chain_head, [source_validator, target_validator]
            )

        assert result == []
