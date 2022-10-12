import logging

import aiohttp

logger = logging.getLogger(__name__)


async def send_to_oracle(url, data, session: aiohttp.ClientSession):
    async with session.post(url, data=data) as response:
        return await response.read()
