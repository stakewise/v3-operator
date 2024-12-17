from typing import Any

from gql import Client, gql
from gql.transport.aiohttp import AIOHTTPTransport
from graphql import DocumentNode

from src.common.decorators import retry_gql_errors
from src.config.settings import DEFAULT_RETRY_TIME, GRAPH_API_TIMEOUT, settings

GRAPH_PAGE_SIZE = 100


class GraphClient:
    gql_client: Client

    def __init__(self) -> None:
        transport = AIOHTTPTransport(
            url=settings.network_config.STAKEWISE_API_URL,
            timeout=GRAPH_API_TIMEOUT,
        )
        self.gql_client = Client(transport=transport)

    async def get_vault_validators(self, vault: str) -> list[str]:
        query = gql(
            """
            query Validators($vaultAddress: String!, $first: Int, $skip: Int) {
              vaultValidators(
                vaultAddress: $vaultAddress
                statusIn: ["active_ongoing"]
                first: $first
                skip: $skip
              ) {
                publicKey
              }
            }
            """
        )

        variables: dict[str, Any] = {'vaultAddress': vault, 'first': GRAPH_PAGE_SIZE, 'skip': 0}

        all_validators: list[str] = []
        while True:
            res = await self.run_query(query, variables)
            validators_page = res['vaultValidators']
            all_validators.extend(validator['publicKey'] for validator in validators_page)

            if len(validators_page) < GRAPH_PAGE_SIZE:
                break

            variables['skip'] += GRAPH_PAGE_SIZE

        return all_validators

    @retry_gql_errors(delay=DEFAULT_RETRY_TIME)
    async def run_query(self, query: DocumentNode, params: dict | None = None) -> dict:
        result = await self.gql_client.execute_async(query, variable_values=params)
        return result
