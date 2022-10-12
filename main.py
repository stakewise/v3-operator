import asyncio
import logging
import threading
import time
from urllib.parse import urlparse

import aiohttp
from eth_typing import HexStr
from web3 import Web3
from web3.types import BlockNumber

from src.common.beacon import get_finality_checkpoints, get_validator
from src.common.database import Database, check_db_connection
from src.common.ipfs import ipfs_fetch
from src.common.oracles import send_to_oracle
from src.config.settings import (CONFIRMATION_BLOCKS, DATABASE_URL,
                                 ENABLE_HEALTH_SERVER, HEALTH_SERVER_HOST,
                                 HEALTH_SERVER_PORT, LOG_LEVEL, NETWORK_CONFIG,
                                 PROCESS_INTERVAL, SENTRY_DSN)
from src.eth.clients import get_web3_client
from src.eth.queries import (get_oracles_endpoints, get_registered_validators,
                             get_vault_balance, get_vault_validators_root)
from src.health_server import (create_health_server_runner, health_routes,
                               start_health_server)
from src.shard.shard import split_to_shards
from src.types import ValidatorDepositData
from src.utils import InterruptHandler

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%m-%d %H:%M",
    level=LOG_LEVEL,
)
logging.getLogger("backoff").addHandler(logging.StreamHandler())

logger = logging.getLogger(__name__)

w3 = Web3()
session = aiohttp.ClientSession()


async def main() -> None:
    database = Database(
        db_url=DATABASE_URL,
    )

    await init_checks()

    # fetch validators
    await update_validators_state(database)

    interrupt_handler = InterruptHandler()
    w3_client = get_web3_client()

    registering_keys = {}
    block_number = 0

    while not interrupt_handler.exit:
        try:
            current_block_number = w3_client.eth.block_number - CONFIRMATION_BLOCKS

            if current_block_number < block_number + 100:
                continue

            pool_balance = get_vault_balance(block_number)

            if not pool_balance >= NETWORK_CONFIG['VALIDATOR_DEPOSIT']:
                # not enough balance to register next validator
                continue

            vault_validators_link: str = get_vault_validators_root(current_block_number)

            vault_val_data: ValidatorDepositData = ValidatorDepositData(
                ipfs_fetch(vault_validators_link)
            )

            # select validator
            validators_deposit_data: list[ValidatorDepositData] = vault_val_data[0]
            if not validators_deposit_data:
                logger.warning("Run out of validator keys")
                return

            # select validator
            public_key: HexStr = ...
            validator_index: int = 1

            registering_keys[public_key] = {
                "block_number": block_number,
                "validator_index": validator_index,
            }

            await send_exit_signature(public_key, block_number)

        except BaseException as e:
            logger.exception(e)

        finally:
            time.sleep(PROCESS_INTERVAL)


async def send_exit_signature(validator_pubkey, block_number: BlockNumber):
    # create exit signature
    validator_exit_message = ...

    # split to shards
    oracles_endpoints = get_oracles_endpoints(block_number)

    shards = split_to_shards(
        validator_exit_message,
        len(oracles_endpoints),
        len(oracles_endpoints) / 3 * 2
    )

    # send shards
    tasks = []
    for index, oracles_endpoint in enumerate(oracles_endpoints):
        tasks.append(send_to_oracle(
            url=oracles_endpoint,
            data={"data": shards[index]},
            session=session,
        ))

    await asyncio.gather(*tasks)


async def process_active_registrations(
        registering_keys: dict,
        block_number: BlockNumber
):
    # check active sharding process
    for pub_key, validator_data in registering_keys.items():
        beacon_data = await get_validator(pub_key)
        if not beacon_data:
            continue

        if validator_data['index'] == beacon_data['index']:
            del registering_keys[pub_key]
        else:
            await send_exit_signature(pub_key, block_number)


async def init_checks():
    # check database connection
    logger.info("Checking connection to database...")
    check_db_connection(DATABASE_URL)

    # check ETH1 API connection
    logger.info("Checking connection to execution layer node...")
    w3_client = get_web3_client()
    w3_client.isConnected()
    parsed_uri = "{uri.scheme}://{uri.netloc}".format(
            uri=urlparse(NETWORK_CONFIG["ETH1_ENDPOINT"])
        )
    logger.info("Connected to execution layer node at %s", parsed_uri)

    # check consensus layer API connection
    logger.info("Checking connection to consensus node...")
    await get_finality_checkpoints(session)
    parsed_uri = "{uri.scheme}://{uri.netloc}".format(
        uri=urlparse(NETWORK_CONFIG["ETH2_ENDPOINT"])
    )
    logger.info("Connected to ETH2 node at %s", parsed_uri)


async def update_validators_state(database):
    # todo: save last block number
    validators = get_registered_validators()
    database.add_validators(validators)


if __name__ == "__main__":
    if ENABLE_HEALTH_SERVER:
        t = threading.Thread(
            target=start_health_server,
            args=(create_health_server_runner(health_routes),),
            daemon=True,
        )
        logger.info(
            "Starting operator server at http://%s:%s",
            HEALTH_SERVER_HOST,
            HEALTH_SERVER_PORT
        )
        t.start()

    if SENTRY_DSN:
        import sentry_sdk
        from sentry_sdk.integrations.logging import ignore_logger

        sentry_sdk.init(SENTRY_DSN, traces_sample_rate=0.1)
        ignore_logger("backoff")

    asyncio.run(main())
