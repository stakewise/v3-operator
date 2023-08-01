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
    2. Sign the exit message with every private key share and encrypt exit signatures with oracles' public keys.
    3. Send encrypted exit signatures to all the oracles and receive registration signatures from them.
4. Send transaction to Vault contract to register the validator.

### Exit signatures rotation

Exit signatures from the previous section are valid only for current and next consensus network forks.
The operator periodically checks active validators for Vault and if some signatures become outdated after new fork
release the operator will submit
a signature update transaction to the Vault.

### Vault state update (optional)

The oracles periodically submit consensus rewards of all the vaults to the Keeper contract.
By default, every vault pulls these updates on the user interaction with the vault (deposit, withdraw, etc.), but it
also can be done by the vault operator by passing the `--harvest-vault` flag to the `start` command.

## Usage

## Step 0. Download operator binary

Download and decompress the binary file from [releases page](https://github.com/stakewise/v3-operator/releases).

## Step 1. Generate keystores & deposit data

Operator generates mnemonic, keystores, deposit data for the validators. It also generates hot wallet used to submit
validator registration transactions.

#### How can I find the Vault address?

If you are creating a new Vault:

1. Go to [StakeWise vaults](https://pacific.stakewise.io/vaults)
2. Connect with your wallet
3. Click on "Create Vault"
4. Process vault setup step by step
5. Once vault is deployed go to its page

You can find the vault address either in the URL bar or in the "Contract address" field by scrolling to the "Details" at
the bottom of the page.

### 1. Init vault config

Create the vault config and mnemonic used to derive validator keys.

```bash
./operator init
```

```
Enter the network name (goerli) [goerli]:
Enter your vault address: 0x3320ad928c20187602a2b2c04eeaa813fa899468
Choose your mnemonic language (chinese_simplified, chinese_traditional, czech, english, italian, korean, portuguese, spanish) [english]:
This is your seed phrase. Write it down and store it safely, it is the ONLY way to recover your validator keys.

pumpkin anxiety private salon inquiry ....


Press any key when you have written down your mnemonic.

Please type your mnemonic (separated by spaces) to confirm you have written it down

: pumpkin anxiety private salon inquiry ....

done.
Successfully initialized configuration for vault 0x3320ad928c20187602a2b2c04eeaa813fa899468
```

#### Options:

- `--network` - The network of your vault.
- `--vault` - The vault address.
- `--language` - The mnemonic language.
- `--no-verify` - Skips mnemonic verification when provided.
- `--data-dir` - Path where the vault data will be placed. Default is ~/.stakewise.

**NB! You must store the generated mnemonic in a secure cold storage.
It will allow you to restore the keys in case the Vault will get corrupted or lost.**

### 2. Create keys

Creates deposit data and validator keystores for operator service:

```bash
./operator create-keys
```

```
Enter the vault address: 0x3320a...68
Enter the number of the validator keys to generate: 10
Enter the mnemonic for generating the validator keys: pumpkin anxiety private salon inquiry ....
Creating validator keys:		  [####################################]  10/10
Generating deposit data JSON		  [####################################]  10/10
Exporting validator keystores		  [####################################]  10/10

Done. Generated 10 keys for 0x3320a...68 vault.
Keystores saved to /home/user/.stakewise/0x3320ad928c20187602a2b2c04eeaa813fa899468/keystores file
Deposit data saved to /home/user/.stakewise/0x3320ad928c20187602a2b2c04eeaa813fa899468/keystores/deposit_data.json file
```

#### Options:

- `--mnemonic` - The mnemonic for generating the validator keys.
- `--count` - The number of the validator keys to generate.
- `--vault` - The vault to generate the keystores and deposit data for.
- `--per-keystore-password` - Creates separate password file for each keystore.
- `--data-dir` - Path where the vault data will be placed. Default is ~/.stakewise.

**NB! You must upload the deposit data to your vault:**
1. Go to [StakeWise vaults](https://pacific.stakewise.io/vaults)
2. Connect with your wallet
3. Go to the "Created" tab and click on the vault
4. In the upper right corner, click on settings, open the "Deposit data" tab
5. Upload generated deposit data file and click "Save"

### 3. Create wallet

Creates the encrypted hot wallet from the mnemonic.
The hot wallet is used to submit validator registration transaction. You must send some ETH (DAI for Gnosis) to the
wallet for the gas expenses. The validator registration costs around 0.01 ETH with 30 Gwei gas price. You must keep an
eye on your wallet balance, otherwise validators will stop registering.

```bash
./operator create-wallet
```

```
Enter the vault address: 0x3320a...68
Enter the mnemonic for generating the wallet: pumpkin anxiety private salon inquiry ...
Done. The wallet and password saved to /home/user/.stakewise/0x3320a...68/wallet directory. The wallet address is: 0x239B...e3Cc
```

#### Options:

- `--vault` - The vault to generate the wallet for.
- `--mnemonic` - The mnemonic for generating the wallet.
- `--data-dir` - Path where the vault data will be placed. Default is ~/.stakewise.

Or you can use any of the tools available for generating the hot wallet. For example,

- [Metamask](https://metamask.io/)
    1. [Generate wallet](https://metamask.zendesk.com/hc/en-us/articles/360015289452-How-to-create-an-additional-account-in-your-wallet)
    2. [Export wallet](https://metamask.zendesk.com/hc/en-us/articles/360015289632-How-to-export-an-account-s-private-key)
- [MyEtherWallet Offline](https://help.myetherwallet.com/en/articles/6512619-using-mew-offline-current-mew-version-6)

## Step 2. Install execution node

The execution node is used to fetch data from the Vault contract and to submit transactions. Any execution client that
supports [ETH Execution API specification](https://ethereum.github.io/execution-apis/api-documentation/) can be used:

- [Nethermind](https://launchpad.ethereum.org/en/nethermind) (Ethereum, Gnosis)
- [Besu](https://launchpad.ethereum.org/en/besu) (Ethereum)
- [Erigon](https://launchpad.ethereum.org/en/erigon) (Ethereum)
- [Geth](https://launchpad.ethereum.org/en/geth) (Ethereum)

## Step 3. Install consensus node

The consensus node is used to fetch consensus fork data required for generating exit signatures. Any consensus client
that
supports [ETH Beacon Node API specification](https://ethereum.github.io/beacon-APIs/#/) can be used:

- [Lighthouse](https://launchpad.ethereum.org/en/lighthouse) (Ethereum, Gnosis)
- [Nimbus](https://launchpad.ethereum.org/en/nimbus) (Ethereum)
- [Prysm](https://launchpad.ethereum.org/en/prysm) (Ethereum)
- [Teku](https://launchpad.ethereum.org/en/teku) (Ethereum, Gnosis)

## Step 4. Run operator service

#### Option 1. From binary executable file

See [releases page](https://github.com/stakewise/v3-operator/releases) to download and decompress the corresponding
binary file. Start the binary with the following command:

```sh
./operator start --vault=0x3320ad928c20187602a2b2c04eeaa813fa899468  --consensus-endpoints=https://consensus.com --execution-endpoints=https://execution.com
```

Or you can use environment variables. Check [.env.example](.env.example) file for details

#### Option 2. Use Docker image

Build Docker image:

```sh
docker build --pull -t stakewiselabs/v3-operator .
```

or pull existing one:

```sh
docker pull europe-west4-docker.pkg.dev/stakewiselabs/public/v3-operator:latest
```

You have to mount keystores and deposit data folders into docker container.

Start the container with the following command:

```sh
docker run --restart on-failure:10 \
  -v ~/.stakewise/:/data \
  europe-west4-docker.pkg.dev/stakewiselabs/public/v3-operator:latest \
  src/main.py start \
  --vault=0x3320ad928c20187602a2b2c04eeaa813fa899468 \
  --data-dir=/data \
  --consensus-endpoints=https://example.com \
  --execution-endpoints=https://example.com
```

Docker compose is an option if you prefer a declarative style instead of long one-liners.
Example `docker-compose.yml` included. Adjust it for yourself and run:

```sh
docker-compose up
```

#### Option 3. Use Kubernetes helm chart

You can use [Operator V3 helm chart](https://github.com/stakewise/helm-charts/tree/main/charts/v3-operator) to host
operator in Kubernetes

#### Option 4. Build from source

Build requirements:

- [Python 3.10+](https://www.python.org/downloads/)
- [Poetry](https://python-poetry.org/docs/)

Install dependencies and start operator:

```sh
poetry install --only main
PYTHONPATH=. poetry run python src/main.py start \
--vault=0x3320ad928c20187602a2b2c04eeaa813fa899468 \
--consensus-endpoints=https://example.com \
--execution-endpoints=https://example.com
```

### Environment variables

Operator service also can be configured via environment variables instead of cli flags.
Copy [.env.example](.env.example) file to `.env` file and fill it with correct values.
Make sure that file paths in .env file represent vault data and client endpoints. You must load environment variables before running the operator.

```sh
export $(grep -v '^#' .env | xargs)
./operator start
```

## Misc commnads

### Validators voluntary exit

Performs a voluntary exit for active vault validators.

```bash
./operator validator-exit
```

```
Enter the comma separated list of API endpoints for consensus nodes: https://example.com
Enter your vault address: 0x3320ad928c20187602a2b2c04eeaa813fa899468
Are you sure you want to exit 3 validators with indexes: 513571, 513572, 513861? [y/N]: y
Validators 513571, 513572, 513861 exits successfully initiated
```

#### Options:

- `--network` - The network of your vault.
- `--vault` - The vault address.
- `--consensus-endpoints` - Comma separated list of API endpoints for consensus nodes.
- `--count` - The number of validators to exit. By default, command will force exit all active vault validators.
- `--data-dir` - Path where the vault data will be placed. Default is ~/.stakewise.
- `--verbose` - Enable debug mode. Default is false.


### Recover your vault data directory and keystores using this command.

```bash
./operator recover
```

```
Enter the mnemonic for generating the validator keys: [Your Mnemonic Here]
Enter your vault address: 0x3320ad928c20187602a2b2c04eeaa813fa899468
Enter comma separated list of API endpoints for execution nodes: https://example.com
Enter comma separated list of API endpoints for consensus nodes: https://example.com
Enter the network name: goerli
Vault data and keystores have been successfully recovered at `~/.stakewise/{vault_addr}/keystores`.
```

#### Options:

- `--data-dir` - Path where the vault data will be placed. Default is ~/.stakewise.
- `--per-keystore-password` - Creates separate password file for each keystore.
- `--mnemonic` - The mnemonic for generating the validator keys.
- `--vault` - The vault address.
- `--execution-endpoints` - Comma separated list of API endpoints for execution nodes.
- `--consensus-endpoints` - Comma separated list of API endpoints for consensus nodes.
- `--network` - The network of your vault. Default is Goerli.

> Note: For security purposes, make sure to protect your mnemonic as it can be used to generate your validator keys. Always verify the network and endpoints before running the command.

## Monitoring Operator with Prometheus

Operator supports monitoring using Prometheus by providing a `/metrics` endpoint that Prometheus can scrape to gather
various metrics.

### Prerequisites:

1. Operator application running and accessible.
2. Prometheus server installed and running.
3. Basic knowledge of how to configure Prometheus targets.
4. [Grafana Dashboard](https://grafana.com/grafana/dashboards/19060-v3-operator/) for `v3-operator` installed

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

You can also specify them by providing `--metrics-port` and `--metrics-host` flags to the `start` command.

Now, Operators's metrics will be available at http://[METRICS_HOST]:[METRICS_PORT]/metrics.

Configure Prometheus:

To monitor Operator, you will need to configure Prometheus to scrape metrics from the exposed `/metrics` endpoint.

Add the following job configuration in your Prometheus configuration file (`prometheus.yml`):

```yaml
scrape_configs:
  - job_name: 'operator'
    scrape_interval: 30s
    static_configs:
      - targets: [ '<METRICS_HOST>:<METRICS_PORT>' ]
```

Replace `<METRICS_HOST>` and `<METRICS_PORT>` with the values you've set in Operator.

This configuration tells Prometheus to scrape metrics from Operator every 30 seconds.

# Contacts

- Dmitri Tsumak - dmitri@stakewise.io
- Alexander Sysoev - alexander@stakewise.io
- Evgeny Gusarov - evgeny@stakewise.io
