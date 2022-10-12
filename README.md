# StakeWise Operator manager V3

## Description

Operator service is responsible for saving exit signature shards of the new validators in the StakeWise network.


### Dependencies

#### Graph Node

The [Graph Node](https://github.com/graphprotocol/graph-node) from the Graph Protocol is used for syncing smart
contracts data and allows oracle to perform complex queries using GraphQL. Either self-hosted (preferred)
or `https://api.thegraph.com/subgraphs/name/stakewise/stakewise-<network>`
endpoint can be used.

#### ETH2 Node

The ETH2 node is used to fetch StakeWise validators data (statuses, balances). Any ETH2 client that
supports [ETH2 Beacon Node API specification](https://ethereum.github.io/beacon-APIs/#/) can be used:

- [Lighthouse](https://launchpad.ethereum.org/en/lighthouse)
- [Nimbus](https://launchpad.ethereum.org/en/nimbus)
- [Prym](https://launchpad.ethereum.org/en/prysm). Make sure to provide `--slots-per-archive-point` flag. See [Archival Beacon Node](https://docs.prylabs.network/docs/advanced/beacon_node_api/)
- [Teku](https://launchpad.ethereum.org/en/teku)
- [Infura](https://infura.io/docs/eth2) (hosted)

### Operator Usage

1. Move to `deploy/<network>` directory

```shell script
cd deploy/mainnet
```

2. Create an edit environment file

```shell script
cp .env.example .env
```

3. Run with [docker-compose](https://docs.docker.com/compose/). The docker-compose version must be **v1.27.0+**.

```shell script
docker-compose up -d
```

# Local development
### Mac OS
- `brew install postgresql openssl`
- `export LDFLAGS="-L/usr/local/opt/openssl@1.1/lib" export CPPFLAGS="-I/usr/local/opt/openssl@1.1/include"`
### Setup
- Install `poetry`
- `poetry install`
- `poetry shell`

### Run
- `poetry shell`
- `python src/main.py`
### Test
- `pipenv shell`
- `pytest -s src/tests`

# Contacts
- Alexander Sysoev - alexander@stakewise.io
- Dmitri Tsumak - dmitri@stakewise.io
