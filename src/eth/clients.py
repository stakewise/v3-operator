import logging

from web3 import Web3
from web3.middleware import (construct_sign_and_send_raw_middleware,
                             geth_poa_middleware)

from src.config.settings import NETWORK_CONFIG

logger = logging.getLogger(__name__)


def get_web3_client() -> Web3:
    """Returns instance of the Web3 client."""
    endpoint = NETWORK_CONFIG["ETH1_ENDPOINT"]

    # Prefer WS over HTTP
    if endpoint.startswith("ws"):
        w3 = Web3(Web3.WebsocketProvider(endpoint, websocket_timeout=60))
        logger.warning("Web3 websocket endpoint=%s", endpoint)

    elif endpoint.startswith("http"):
        w3 = Web3(Web3.HTTPProvider(endpoint))
        logger.warning("Web3 HTTP endpoint=%s", endpoint)
    else:
        w3 = Web3(Web3.IPCProvider(endpoint))
        logger.warning("Web3 HTTP endpoint=%s", endpoint)

    if NETWORK_CONFIG["IS_POA"]:
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)
        logger.warning("Injected POA middleware")

    account = w3.eth.account.from_key(NETWORK_CONFIG["PRIVATE_KEY"])
    w3.middleware_onion.add(construct_sign_and_send_raw_middleware(account))
    logger.warning("Injected middleware for capturing transactions and sending as raw")

    w3.eth.default_account = account.address
    logger.info("Configured default account %s", w3.eth.default_account)

    return w3
