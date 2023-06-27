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
# Stakewise V3 key manager

Key manager generates validators keys and deposit data for the validators, generates mnemonic and hot wallet. Also it helps to manage validators keys in web3signer infrastructure.

See [releases page](https://github.com/stakewise/key-manager/releases) to download and decompress the corresponding binary files.

## Key management commands

### 1. Create mnemonic
Create the mnemonic used to derive validator keys.
```bash
./key-manager create-mnemonic --language english
```
```
This is your seed phrase. Write it down and store it safely, it is the ONLY way to recover your validator keys.

pumpkin anxiety private salon inquiry ....


Press any key when you have written down your mnemonic.

Please type your mnemonic (separated by spaces) to confirm you have written it down

: pumpkin anxiety private salon inquiry ....

done.
```
#### Options:
- `--language` - Choose your mnemonic language
- `--no-verify` - Skips mnemonic verification when provided.

**NB! You must store the generated mnemonic in a secure cold storage.
It will allow you to restore the keys in case the Vault will get corrupted or lost.**

### 2. Create keys
Creates deposit data and validator keystores files for operator service:

```bash
./key-manager create-keys
```
```
Enter the number of the validator keys to generate: 10
Enter the mnemonic for generating the validator keys: pumpkin anxiety private salon inquiry ....
Enter the network name (goerli) [goerli]:
Enter the vault address for which the validator keys are generated: 0x56FED...07E7
Enter the mnemonic start index for generating validator keys [0]:
Creating validator keys:		  [####################################]  10/10
Generating deposit data JSON		  [####################################]  10/10
Exporting validator keystores		  [####################################]  10/10

Done. Generated 10 keys for 0x56FED...07E7 vault.
Keystores saved to ./data/keystores file
Deposit data saved to ./data/deposit_data.json file
Next mnemonic start index saved to ./mnemonic_next_index.txt file
```
#### Options:
- `--network` - The network to generate the deposit data for.
- `--mnemonic` - The mnemonic for generating the validator keys.
- `--count` - The number of the validator keys to generate.
- `--vault` or `--withdrawal-address` -The withdrawal address where the funds will be sent after validators’ withdrawals.
- `--admin` - The vault admin address.
- `--vault-type` - The vault type.
- `--execution-endpoint` - The endpoint of the execution node used for computing the with.
- `--deposit-data-file` - The path to store the deposit data file. Defaults to ./data/deposit_data.json.
- `--keystores` - The directory to store the validator keys in the EIP-2335 standard. Defaults to ./data/keystores.
- `--password-file` - The path to store randomly generated password for encrypting the keystores. Defaults to ./data/keystores/password.txt.
- `--mnemonic-start-index` - The index of the first validator keys you wish to generate. If this is your first time generating keys with this mnemonic, use 0. If you have generated keys using this mnemonic before, add --mnemonic-next-index-file flag or specify the next index from which you want to start generating keys from (eg, if you've generated 4 keys before (keys #0, #1, #2, #3) then enter 4 here.
- `--mnemonic-next-index-file` - The path where to store the mnemonic index to use for generating next validator keys. Used to always generate unique validator keys. Defaults to ./mnemonic_next_index.txt.


### 3. Create wallets

Creates the encrypted hot wallet from the mnemonic.

```bash
./key-manager create-wallet
```
```
Enter the mnemonic for generating the wallet: pumpkin anxiety private salon inquiry ...
Done. Wallet 0xf5fF7...B914a-1677838759.json saved to ./wallet directory
```
#### Options:
- `--mnemonic` - The mnemonic for generating the validator keys.
- `--wallet-dir` - The directory to save encrypted wallet and password files. Defaults to ./wallet.


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

##### Debian based image
```sh
docker build --pull -t stakewiselabs/v3-operator .
```

or pull existing one:
```sh
docker pull europe-west4-docker.pkg.dev/stakewiselabs/public/v3-operator:latest
```

##### Alpine based image

```sh
docker build -f Dockerfile.alpine --pull -t stakewiselabs/v3-operator .
```

or pull existing one:
```sh
docker pull europe-west4-docker.pkg.dev/stakewiselabs/public/v3-operator:<release>-alpine
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

## Monitoring Operator with Prometheus

Operator supports monitoring using Prometheus by providing a `/metrics` endpoint that Prometheus can scrape to gather various metrics.

### Prerequisites:

1. Operator application running and accessible.
1. Prometheus server installed and running.
1. Basic knowledge of how to configure Prometheus targets.

Setup Operator for Monitoring:

Operator provides the flexibility to define the host and port for the metrics endpoint via environment variables:

- `METRICS_HOST`: This defines the hostname or IP on which the metrics endpoint will be available.
- `METRICS_PORT`: This defines the port on which the metrics endpoint will be available.

Ensure that these environment variables are set as per your requirements.

For example:

```bash
export METRICS_HOST=0.0.0.0
export METRICS_PORT=9100
```

Now, Operators's metrics will be available at http://[METRICS_HOST]:[METRICS_PORT]/metrics.

Configure Prometheus:

To monitor Operator, you will need to configure Prometheus to scrape metrics from the exposed `/metrics` endpoint.

Add the following job configuration in your Prometheus configuration file (`prometheus.yml`):

```yaml
scrape_configs:
  - job_name: 'operator'
    scrape_interval: 30s
    static_configs:
      - targets: ['<METRICS_HOST>:<METRICS_PORT>']
```

Replace `<METRICS_HOST>` and `<METRICS_PORT>` with the values you've set in Operator.

This configuration tells Prometheus to scrape metrics from Operator every 30 seconds.

# Contacts
- Dmitri Tsumak - dmitri@stakewise.io
- Alexander Sysoev - alexander@stakewise.io
- Evgeny Gusarov - evgeny@stakewise.io
