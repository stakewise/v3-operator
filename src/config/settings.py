from decouple import Csv, config

from src.config.networks import MAINNET, NETWORKS

# common
LOG_LEVEL = config("LOG_LEVEL", default="INFO")

NETWORK = config(
    "NETWORK",
    default=MAINNET,
)

NETWORK_CONFIG = NETWORKS[NETWORK]

# health server settings
ENABLE_HEALTH_SERVER = config("ENABLE_HEALTH_SERVER", default=False, cast=bool)
HEALTH_SERVER_PORT = config("HEALTH_SERVER_PORT", default=8080, cast=int)
HEALTH_SERVER_HOST = config("HEALTH_SERVER_HOST", default="127.0.0.1", cast=str)

# required confirmation blocks
CONFIRMATION_BLOCKS: int = config("CONFIRMATION_BLOCKS", default=15, cast=int)

PROCESS_INTERVAL = config("PROCESS_INTERVAL", default=10, cast=int)

# database
DATABASE_URL = config("DATABASE_URL")

# ipfs

IPFS_FETCH_ENDPOINTS = config(
    "IPFS_FETCH_ENDPOINTS",
    cast=Csv(),
    default="http://cloudflare-ipfs.com,https://ipfs.io,https://gateway.pinata.cloud",
)

LOCAL_IPFS_CLIENT_ENDPOINT = config("LOCAL_IPFS_CLIENT_ENDPOINT", default="")

# infura
INFURA_IPFS_CLIENT_ENDPOINT = config(
    "INFURA_IPFS_CLIENT_ENDPOINT",
    default="/dns/ipfs.infura.io/tcp/5001/https",
)
INFURA_IPFS_CLIENT_USERNAME = config("INFURA_IPFS_CLIENT_USERNAME", default="")
INFURA_IPFS_CLIENT_PASSWORD = config("INFURA_IPFS_CLIENT_PASSWORD", default="")

# extra pins to pinata for redundancy
IPFS_PINATA_PIN_ENDPOINT = config(
    "IPFS_PINATA_ENDPOINT", default="https://api.pinata.cloud/pinning/pinJSONToIPFS"
)
IPFS_PINATA_API_KEY = config("IPFS_PINATA_API_KEY", default="")
IPFS_PINATA_SECRET_KEY = config(
    "IPFS_PINATA_SECRET_KEY",
    default="",
)

# sentry config
SENTRY_DSN = config("SENTRY_DSN", default="")
