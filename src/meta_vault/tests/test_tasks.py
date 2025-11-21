from contextlib import contextmanager
from unittest import mock

import pytest
from eth_typing import ChecksumAddress

from src.meta_vault.tasks import meta_vault_tree_update_state, multicall_contract
from src.meta_vault.tests.factories import create_vault
from src.meta_vault.typings import Vault


@pytest.mark.usefixtures('fake_settings', 'setup_test_clients')
class TestMetaVaultTreeUpdateStateCalls:
    async def test_basic(self):
        # Arrange
        meta_vault = create_vault(is_meta_vault=True, sub_vaults_count=2)
        sub_vault_0 = create_vault(address=meta_vault.sub_vaults[0])
        sub_vault_1 = create_vault(address=meta_vault.sub_vaults[1])
        meta_vaults_map = {
            meta_vault.address: meta_vault,
        }
        graph_mock = GraphMock(
            [
                meta_vault,
                sub_vault_0,
                sub_vault_1,
            ]
        )

        # Act
        with self.patch(graph_mock=graph_mock) as tx_aggregate_mock:
            await meta_vault_tree_update_state(
                root_meta_vault=meta_vault,
                meta_vaults_map=meta_vaults_map,
            )

        # Assert
        calls = tx_aggregate_mock.call_args[0][0]
        assert len(calls) == 3
        assert [c[0] for c in calls] == [
            meta_vault.sub_vaults[0],
            meta_vault.sub_vaults[1],
            meta_vault.address,
        ]

    async def test_nested_meta_vault_basic(self):
        # Arrange
        meta_vault = create_vault(is_meta_vault=True, sub_vaults_count=2)

        # sub vault 0 is meta vault, sub vault 1 is regular vault
        sub_vault_0 = create_vault(
            address=meta_vault.sub_vaults[0], is_meta_vault=True, sub_vaults_count=2
        )
        sub_vault_1 = create_vault(address=meta_vault.sub_vaults[1])

        # sub vaults of sub vault 0
        sub_vault_2 = create_vault(address=sub_vault_0.sub_vaults[0])
        sub_vault_3 = create_vault(address=sub_vault_0.sub_vaults[1])

        meta_vaults_map = {
            meta_vault.address: meta_vault,
            sub_vault_0.address: sub_vault_0,
        }
        graph_mock = GraphMock(
            [
                meta_vault,
                sub_vault_0,
                sub_vault_1,
                sub_vault_2,
                sub_vault_3,
            ]
        )

        # Act
        with self.patch(graph_mock=graph_mock) as tx_aggregate_mock:
            await meta_vault_tree_update_state(
                root_meta_vault=meta_vault,
                meta_vaults_map=meta_vaults_map,
            )

        # Assert
        calls = [c[0][0] for c in tx_aggregate_mock.call_args_list]
        assert [[addr for addr, _ in c] for c in calls] == [
            [
                sub_vault_2.address,
                sub_vault_3.address,
                sub_vault_0.address,
            ],
            [
                sub_vault_1.address,
                meta_vault.address,
            ],
        ]

    @contextmanager
    def patch(self, graph_mock: 'GraphMock'):
        with mock.patch(
            'src.meta_vault.tasks.graph_get_vaults',
            graph_mock.graph_get_vaults,
        ), mock.patch(
            'src.meta_vault.tasks.get_claimable_sub_vault_exit_requests', return_value=[]
        ), mock.patch(
            'src.meta_vault.tasks.is_meta_vault_rewards_nonce_outdated',
            return_value=False,
        ), mock.patch.object(
            multicall_contract, 'tx_aggregate', return_value='0x123'
        ) as tx_aggregate_mock, mock.patch(
            'src.meta_vault.tasks.execution_client.eth.wait_for_transaction_receipt',
        ):
            yield tx_aggregate_mock


class GraphMock:
    def __init__(self, vaults: list[ChecksumAddress]):
        self._vaults = {vault.address: vault for vault in vaults}

    async def graph_get_vaults(self, vaults: list[ChecksumAddress]) -> dict[ChecksumAddress, Vault]:
        """
        Simulate fetching vaults from the graph
        """
        res = {}
        for vault_address in vaults:
            if vault_address not in self._vaults:
                continue
            res[vault_address] = self._vaults[vault_address]

        return res
