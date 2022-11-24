import logging

from web3 import Web3
from web3.eth import AsyncEth
from web3.middleware import async_geth_poa_middleware
from web3.net import AsyncNet

from src.common.utils import Singleton
from src.config.settings import EXECUTION_ENDPOINT, NETWORK_CONFIG

logger = logging.getLogger(__name__)


class ExecutionClient(metaclass=Singleton):
    web3: Web3 | None = None

    def get_client(self) -> Web3:
        if self.web3:
            return self.web3

        self.web3 = Web3(
            Web3.AsyncHTTPProvider(EXECUTION_ENDPOINT),
            modules={'eth': (AsyncEth,), 'net': AsyncNet},
            middlewares=[],
        )
        logger.warning('Web3 HTTP endpoint=%s', EXECUTION_ENDPOINT)

        if NETWORK_CONFIG.IS_POA:
            self.web3.middleware_onion.inject(async_geth_poa_middleware, layer=0)
            logger.warning('Injected POA middleware')

        return self.web3


class LightExecutionClient(metaclass=Singleton):
    web3: Web3 | None = None

    def get_client(self) -> Web3:
        if self.web3:
            return self.web3

        provider = Web3.HTTPProvider(EXECUTION_ENDPOINT)
        # Remove the default JSON-RPC retry middleware
        # as it correctly cannot handle eth_getLogs block range
        # throttle down.
        provider.middlewares.clear()

        self.web3 = Web3(provider)
        logger.warning('Light Web3 HTTP endpoint=%s', EXECUTION_ENDPOINT)

        if NETWORK_CONFIG.IS_POA:
            self.web3.middleware_onion.inject(async_geth_poa_middleware, layer=0)
            logger.warning('Injected POA middleware')

        return self.web3
