import asyncio
import logging

from gql import gql
from web3.types import BlockNumber

from src.common.clients import graph_client
from src.config.settings import settings

logger = logging.getLogger(__name__)


async def wait_for_graph_node_sync(block_number: BlockNumber) -> None:
    """
    Waits until graph node is synced to the provided block number.
    """
    query = gql(
        '''
        query Meta {
          _meta {
            block {
              number
            }
          }
        }
    '''
    )
    while True:
        response = await graph_client.run_query(query)
        graph_block_number = response['_meta']['block']['number']
        if graph_block_number < block_number:
            logger.info(
                'Waiting the graph node node located at %s complete synchronization to block %s.',
                settings.graph_endpoint,
                block_number,
            )
            await asyncio.sleep(settings.network_config.SECONDS_PER_BLOCK)
            continue
        return

    return
