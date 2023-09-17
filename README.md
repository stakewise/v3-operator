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

Exit signatures from the previous section can become invalid if the oracles set changes. For example, if oracle's
private key gets compromised, the DAO will have to propose an update of the oracles set that will trigger exit signature
rotation.
The operator periodically checks active validators of the Vault and if some exit signatures become outdated, the
operator will submit a signature update transaction to the Vault.

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

### How can I find the Vault address?

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

```sh
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

#### Options

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

```sh
Enter the vault address: 0x3320a...68
Enter the number of the validator keys to generate: 10
Enter the mnemonic for generating the validator keys: pumpkin anxiety private salon inquiry ....
Creating validator keys:    [####################################]  10/10
Generating deposit data JSON    [####################################]  10/10
Exporting validator keystores    [####################################]  10/10

Done. Generated 10 keys for 0x3320a...68 vault.
Keystores saved to /home/user/.stakewise/0x3320ad928c20187602a2b2c04eeaa813fa899468/keystores file
Deposit data saved to /home/user/.stakewise/0x3320ad928c20187602a2b2c04eeaa813fa899468/keystores/deposit_data.json file
```

#### `create-keys` options

- `--mnemonic` - The mnemonic for generating the validator keys.
- `--count` - The number of the validator keys to generate.
- `--vault` - The vault to generate the keystores and deposit data for.
- `--per-keystore-password` - Creates separate password file for each keystore.
- `--data-dir` - Path where the vault data is stored. Default is ~/.stakewise.

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

```sh
Enter the vault address: 0x3320a...68
Enter the mnemonic for generating the wallet: pumpkin anxiety private salon inquiry ...
Done. The wallet and password saved to /home/user/.stakewise/0x3320a...68/wallet directory. The wallet address is: 0x239B...e3Cc
```

#### `create-wallet` options

- `--vault` - The vault to generate the wallet for.
- `--mnemonic` - The mnemonic for generating the wallet.
- `--data-dir` - Path where the vault data is stored. Default is ~/.stakewise.

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

### Option 1. From binary executable file

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
Make sure that file paths in .env file represent vault data and client endpoints. You must load environment variables
before running the operator.

```sh
export $(grep -v '^#' .env | xargs)
./operator start
```

## Remote signer

You may not want the operator service to have direct access to the validator
keys. Validator keystores do not need to be present directly in the operator.
The operator can query a remote signer to get signatures for validator
exit messages. Because the validator exit signatures are split up and
shared among oracles, the validator exit message needs to be signed by
specific shares of the validator private key.

These key shares therefore need to be present in your remote signer.

### Remote signer setup

This command will split up the private keys in the keystores directory
into private key shares. The resulting private key shares are
then imported to the remote signer. Local keystores are removed
as a result of this command since they no longer need to be present.

Notes:
- You will need to run this command every time the oracle set
  changes, or the threshold needed to recover exit signatures
  (`exit_signature_recover_threshold`) changes.
- In order to regenerate key shares, make sure to
  adjust the `mnemonic_next_index` value in the vault config.json
  to 0, then run the `create-keys` command, generating the full keystores
  for all your validators. Next, run the `remote-signer-setup` command
  to regenerate and import the new key shares for all your validators
  into the remote signer.
  You can remove the previously generated private key shares from the
  remote signer, they will not be used anymore. This can optionally be
  done by the setup command automatically by using the
  `--remove-existing-keys` flag.

```bash
./operator remote-signer-setup \
 --vault=0x3320ad928c20187602a2b2c04eeaa813fa899468 \
 --remote-signer-url=http://signer:9000
```

```
Successfully generated 11 key shares for 1 private key(s)!
Successfully imported 11 key shares into remote signer.
Removed keystores from local filesystem.
Done. Successfully configured operator to use remote signer for 1 public key(s)!
```

#### `remote-signer-setup` options

- `--vault` - The vault address.
- `--remote-signer-url` - The base URL of the remote signer, e.g. http://signer:9000
- `--remove-existing-keys` - Include this flag to remove any keys present in the signer that are not needed by the operator.
  Can be used to remove outdated keyshares from the remote signer when the set of oracles changes,
  see note above.
- `--data-dir` - Path where the vault data is stored. Default is ~/.stakewise.
- `--keystores-dir` - The directory with validator keys in the EIP-2335 standard.
- `--execution-endpoints` - Comma separated list of API endpoints for execution nodes.
- `--verbose` - Enable debug mode. Default is false.

### Running the operator

Provide the operator with the URL to your remote signer instance
using the `--remote-signer-url` flag:

```bash
./operator start --remote-signer-url=http://remote-signer:9000 ...
```

You should see a message similar to this one after starting the operator:

```
Using remote signer at http://remote-signer:9000 for 10 public keys
```


## Misc commands

### Validators voluntary exit

Performs a voluntary exit for active vault validators.

```bash
./operator validators-exit
```

```sh
Enter the comma separated list of API endpoints for consensus nodes: https://example.com
Enter your vault address: 0x3320ad928c20187602a2b2c04eeaa813fa899468
Are you sure you want to exit 3 validators with indexes: 513571, 513572, 513861? [y/N]: y
Validators 513571, 513572, 513861 exits successfully initiated
```

#### `validators-exit` options

- `--network` - The network of your vault.
- `--vault` - The vault address.
- `--consensus-endpoints` - Comma separated list of API endpoints for consensus nodes.
- `--count` - The number of validators to exit. By default, command will force exit all active vault validators.
- `--data-dir` - Path where the vault data is stored. Default is ~/.stakewise.
- `--remote-signer-url` - URL to the remote signer instance.
- `--verbose` - Enable debug mode. Default is false.

### Update vault deposit data

You can do that from the StakeWise web app by going to the settings on the vault page and uploading the deposit data or
by using the following command:

1. Generate deposit data validators root for your vault.

    ```bash
    ./operator get-validators-root
    ```

    ```sh
    Enter the vault address: 0xeEFFFD4C23D2E8c845870e273861e7d60Df49663
    The validator deposit data Merkle tree root: 0x50437ed72066c1a09ee85978f168ac7c58fbc9cd4beb7962c13e68e7faac26d7
    ```

    `get-validators-root` options

    - `--data-dir` - Path where the vault data is stored. Default is ~/.stakewise.
    - `--deposit-data-file` - Path to the file with deposit data. Default is deposit data file located in the vault
      directory.
    - `--vault` - The vault address.

2. Set deposit data root by calling `setValidatorsRoot` function on your vault. You must pass the Merkle tree root generated from the previous command. The ABI of the contract can be found [here](https://github.com/stakewise/v3-core/blob/main/abi/IVaultValidators.json).

  **NB! The function must be called from the keys manager address (vault admin address by default).**

### Recover vault data directory and keystores

```bash
./operator recover
```

```sh
Enter the mnemonic for generating the validator keys: [Your Mnemonic Here]
Enter your vault address: 0x3320ad928c20187602a2b2c04eeaa813fa899468
Enter comma separated list of API endpoints for execution nodes: https://example.com
Enter comma separated list of API endpoints for consensus nodes: https://example.com
Enter the network name: goerli
Found 24 validators, recovering...
Generating keystores  [####################################]  100%
Keystores for vault {vault} successfully recovered to {keystores_dir}
```

#### `recover` options

- `--data-dir` - Path where the vault data will be placed. Default is ~/.stakewise.
- `--per-keystore-password` - Creates separate password file for each keystore.
- `--mnemonic` - The mnemonic for generating the validator keys.
- `--vault` - The vault address.
- `--execution-endpoints` - Comma separated list of API endpoints for execution nodes.
- `--consensus-endpoints` - Comma separated list of API endpoints for consensus nodes.
- `--network` - The network of your vault. Default is Goerli.

> Note: For security purposes, make sure to protect your mnemonic as it can be used to generate your validator keys.
> Always verify the network and endpoints before running the command.

### Web3Signer infrastructure commands

#### 1. Update database

The command encrypts and loads validator keys from keystore files into the database

```bash
./v3-operator update-db --db-url postgresql://postgres:postgres@localhost:5432/web3signer --keystores-dir ./data/keystores --keystores-password-file ./data/keystores/password.txt
Loading keystores...              [####################################]  10/10
Encrypting database keys...
Generated 10 validator keys, upload them to the database? [Y/n]: Y
The database contains 10 validator keys.
Save decryption key: '<DECRYPTION KEYS>'
```

##### update-db options

- `--keystores-dir` - The directory with validator keys in the EIP-2335 standard. Defaults to ./data/keystores.
- `--keystores-password-file` - The path to file with password for encrypting the keystores. Defaults to ./data/keystores/password.txt.
- `--db-url` - The database connection address.
- `--encryption-key` - The key for encrypting database record. If you are upload new keystores use the same encryption key.
- `--no-confirm` - Skips confirmation messages when provided.

**NB! You must store the decryption key in a secure place.
It will allow you to upload new keystores in the existing database**

#### 2. Sync validator configs

Creates validator configuration files for Lighthouse, Prysm, and Teku clients to sign data using keys form database.

```bash
./v3-operator sync-validator
Enter the recipient address for MEV & priority fees: 0xB31...1
Enter the endpoint of the web3signer service: https://web3signer-example.com
Enter the database connection string, ex. 'postgresql://username:pass@hostname/dbname': postgresql://postgres:postgres@localhost/web3signer
Enter the total number of validators connected to the web3signer: 30
Enter the validator index to generate the configuration files: 5

Done. Generated configs with 50 keys for validator #5.
Validator definitions for Lighthouse saved to data/configs/validator_definitions.yml file.
Signer keys for Teku\Prysm saved to data/configs/signer_keys.yml file.
Proposer config for Teku\Prysm saved to data/configs/proposer_config.json file.
```

##### sync-validator options

- `--validator-index` - The validator index to generate the configuration files.
- `--total-validators` - The total number of validators connected to the web3signer.
- `--db-url` - The database connection address.
- `--web3signer-endpoint` - The endpoint of the web3signer service.
- `--fee-recipient` - The recipient address for MEV & priority fees.
- `--disable-proposal-builder` - Disable proposal builder for Teku and Prysm clients.
- `--output-dir` - The directory to save configuration files. Defaults to ./data/configs.

#### 3. Sync Web3Signer config

The command is running by the init container in web3signer pods.
Fetch and decrypt keys for web3signer and store them as keypairs in the output_dir.

Set `DECRYPTION_KEY` env, use value generated by `update-db` command

```bash
./v3-operator sync-web3signer
Enter the folder where web3signer keystores will be saved: /data/web3signer
Enter the database connection string, ex. 'postgresql://username:pass@hostname/dbname': postgresql://postgres:postgres@localhost/web3signer
Web3Signer now uses 7 private keys.
```

##### sync-web3signer options

- `--db-url` - The database connection address.
- `--output-dir` - The folder where Web3Signer keystores will be saved.
- `--decryption-key-env` - The environment variable with the decryption key for private keys in the database.

## Monitoring Operator with Prometheus

Operator supports monitoring using Prometheus by providing a `/metrics` endpoint that Prometheus can scrape to gather
various metrics.

### Prerequisites

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

Now, Operators's metrics will be available at <http://[METRICS_HOST]:[METRICS_PORT]/metrics>.

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

## Contacts

- Dmitri Tsumak - <dmitri@stakewise.io>
- Alexander Sysoev - <alexander@stakewise.io>
- Evgeny Gusarov - <evgeny@stakewise.io>
