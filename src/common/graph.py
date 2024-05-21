from eth_typing import BlockNumber
from gql import Client, gql
from gql.transport.aiohttp import AIOHTTPTransport
from graphql import DocumentNode

from src.config.settings import settings, DEFAULT_RETRY_TIME, GRAPH_API_TIMEOUT
from src.common.decorators import retry_gql_errors

GRAPH_PAGE_SIZE = 100


class GraphClient:
    gql_client: Client
    

    def __init__(self):
        transport = AIOHTTPTransport(url=settings.network_config.STAKEWISE_API_URL, timeout=GRAPH_API_TIMEOUT)
        self.gql_client = Client(transport=transport)

    @retry_gql_errors(delay=DEFAULT_RETRY_TIME)
    async def run_query(self, query: DocumentNode, params: dict | None = None) -> dict:
        result = await self.gql_client.execute_async(query, variable_values=params)
        return result

    async def get_vault_validators(self, vault: str) -> list[str]:
        query = gql(
            """
            query Validators($vaultAddress: String!) {
              vaultValidators(
                vaultAddress: $vaultAddress
                statusIn: "active_ongoing"
              ) {
                publicKey
              }
            }
            """
        )

        variables = {
            "vaultAddress": vault
        }

        res = await self.run_query(query, variables)
        return [validator['publicKey'] for validator in res['vaultValidators']]
