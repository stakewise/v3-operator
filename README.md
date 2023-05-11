# StakeWise V3 Operator

## Introduction

StakeWise Operator is a service that StakeWise Vault operators must run. It is responsible for performing the following
tasks:

### Validator registration

The operator periodically checks whether Vault has accumulated enough assets for registering new validator(s) and sends
a registration transaction to the Vault.

The validator registration process consists of the following steps:

1. Check whether Vault has accumulated enough assets to register a validator (e.g., 32 ETH for Ethereum)
2. Get the next free validator public key from the deposit data file attached to the operator. The validators are
   registered in the same order as specified in the deposit data file.
3. Share the exit signature of the validator with StakeWise Oracles:
    1. Using [Shamir's secret sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing), generate shares for the
       validator's BLS private key. The number of shares is equal to the number of oracles.
    2. Sign the exit message with every private key share and encrypt exit signatures with corresponding oracles' RSA
       public keys.
    3. Send encrypted exit signatures to all the oracles and receive registration signatures from them.
4. Send transaction to Vault contract to register the validator.

## Usage

### Step 1. Install execution node

The execution node is used to fetch data from the Vault contract and to submit transactions. Any execution client that
supports [ETH Execution API specification](https://ethereum.github.io/execution-apis/api-documentation/) can be used:

- [Nethermind](https://launchpad.ethereum.org/en/nethermind) (Ethereum, Gnosis)
- [Besu](https://launchpad.ethereum.org/en/besu) (Ethereum)
- [Erigon](https://launchpad.ethereum.org/en/erigon) (Ethereum)
- [Geth](https://launchpad.ethereum.org/en/geth) (Ethereum)

### Step 2. Install consensus node

The consensus node is used to fetch consensus fork data required for generating exit signatures. Any consensus client
that
supports [ETH Beacon Node API specification](https://ethereum.github.io/beacon-APIs/#/) can be used:

- [Lighthouse](https://launchpad.ethereum.org/en/lighthouse) (Ethereum, Gnosis)
- [Nimbus](https://launchpad.ethereum.org/en/nimbus) (Ethereum)
- [Prysm](https://launchpad.ethereum.org/en/prysm) (Ethereum)
- [Teku](https://launchpad.ethereum.org/en/teku) (Ethereum, Gnosis)

### Step 3. Generate keystores & deposit data

The keystores are used to create exit signatures, and the deposit data is used to register the validators.

The deposit data must comply with the following rules:

- The Vault address must be used as withdrawal address.
- The validator public keys must be new and never seen by the beacon chain.

#### How can I find the Vault address?

If you are creating a new Vault:
1. go to [StakeWise testnet app](https://atlantic.stakewise.io)
2. connect the wallet you will create Vault from
3. click on "Create Vault"
4. reach the "Setup Validator" step
5. the Vault address is specified in the withdrawal address field

If you already have a Vault, you can see its address either in the URL bar or by scrolling to the "Details" at the bottom.

#### Tools to generate keystores and deposit data

You can use any of the following tools:

- [StakeWise key manager](https://github.com/stakewise/key-manager/)
- [Staking Deposit CLI](https://github.com/ethereum/staking-deposit-cli)
- [Wagyu Key Gen](https://github.com/stake-house/wagyu-key-gen)

#### Generating new keystores upon existing ones

The validator public keys must be new and never seen by the beacon chain. This can be achieved using a higher mnemonic
index for every new deposit data. For example, if you've generated four keys before (keys #0, #1, #2, #3), then start
with index 4. [StakeWise key manager](https://github.com/stakewise/key-manager/) stores the index locally and updates
it every time you generate new validator keys.

### Step 4. Generate hot wallet

The hot wallet is used to submit validator registration transaction. You must send some ETH (DAI for Gnosis) to
the wallet for the gas expenses. The validator registration costs around 0.01 ETH with 30 Gwei gas price. You must keep
an eye on your wallet balance, otherwise validators will stop registering.

You can use any of the tools available for generating the hot wallet. For example,

- [Metamask](https://metamask.io/)
    1. [Generate wallet](https://metamask.zendesk.com/hc/en-us/articles/360015289452-How-to-create-an-additional-account-in-your-wallet)
    2. [Export wallet](https://metamask.zendesk.com/hc/en-us/articles/360015289632-How-to-export-an-account-s-private-key)
- [MyEtherWallet Offline](https://help.myetherwallet.com/en/articles/6512619-using-mew-offline-current-mew-version-6)
- [Vanity ETH](https://github.com/bokub/vanity-eth)

### Step 5. Prepare .env file

Copy [.env.example](./.env.example) file to `.env` file and fill it with correct values

### Step 6. Deploy operator

#### Option 1. Download binary executable file

See [releases page](https://github.com/stakewise/v3-operator/releases) to download and decompress the corresponding
binary file. Start the binary with the following command:

```sh
./operator
```

#### Option 2. Use Docker image

Build Docker image:

```sh
docker build --pull -t stakewiselabs/v3-operator .
```

or pull existing one:
```sh
docker pull europe-west4-docker.pkg.dev/stakewiselabs/public/v3-operator:latest
```

Make sure that file paths in .env file represent container paths. For example:
```
DATABASE_DIR=/database
KEYSTORES_PASSWORD_FILE=/data/keystores/password.txt
KEYSTORES_PATH=/data/keystores
DEPOSIT_DATA_PATH=/data/deposit_data.json
```

You have to mount keystores and deposit data folders into docker container.
For example, if your keystores and deposit data file are located in `/home/user/data` folder on a host and you use `/home/user/database` folder on host for the database

Start the container with the following command:

```sh
docker run --restart on-failure:10 \
  --env-file .env \
  -v /home/user/database:/database \
  -v /home/user/data:/data \
  europe-west4-docker.pkg.dev/stakewiselabs/public/v3-operator:latest
```

If you prefer declarative style instead of long one-liners, then docker-compose is an option for you.
Example `docker-compose.yml` included. Adjust it for yourself and run:

```sh
docker-compose up
```


#### Option 3. Use Kubernetes helm chart

You can use [Operator V3 helm chart](https://github.com/stakewise/helm-charts/tree/main/charts/v3-operator) to host operator
in Kubernetes

#### Option 4. Build from source

Build requirements:

- [Python 3.10+](https://www.python.org/downloads/)
- [Poetry](https://python-poetry.org/docs/)

Install dependencies and start operator:
```sh
poetry install --only main
PYTHONPATH=. poetry run python src/main.py
```

# Contacts
- Dmitri Tsumak - dmitri@stakewise.io
- Alexander Sysoev - alexander@stakewise.io
- Evgeny Gusarov - evgeny@stakewise.io
