# StakeWise V3 Operator

1. [What is V3 Operator?]()
2. [Configuring V3 Operator]()
3. [V3 Operator commands]()
4. [Optional Extras]()
5. [Contacts]()





# What is V3 Operator?

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











# Configuring V3 Operator

Ensure your execution and consensus nodes are fully synced and running. Any execution client that supports [ETH Execution API specification](https://ethereum.github.io/execution-apis/api-documentation/), or consensus client that supports [ETH Beacon Node API specification](https://ethereum.github.io/beacon-APIs/#/), can be used, such as:
**Execution**
[Nethermind](https://launchpad.ethereum.org/en/nethermind) (Ethereum, Gnosis), [Besu](https://launchpad.ethereum.org/en/besu) (Ethereum), [Erigon](https://launchpad.ethereum.org/en/erigon) (Ethereum), and [Geth](https://launchpad.ethereum.org/en/geth) (Ethereum).
**Consensus**
[Lighthouse](https://launchpad.ethereum.org/en/lighthouse) (Ethereum, Gnosis), [Nimbus](https://launchpad.ethereum.org/en/nimbus) (Ethereum), [Prysm](https://launchpad.ethereum.org/en/prysm) (Ethereum), and [Teku](https://launchpad.ethereum.org/en/teku) (Ethereum, Gnosis).


## 1. Download and install Operator Service

Operator Service can be run via a binary, built using a docker image, deployed on a Kubernetes cluster using the Operator Helm Chart, or built from source. Decide on your preferred method and follow the respective instructions below.
### Binary
Head to the GitHub repository to find the latest version of Operator Service. Identify the binary file specific to your node hardware, download and decompress it.

You will execute Operator Service commands from within the `V3-operator` folder using the below format (note that the use of flags is optional):
```bash
./operator COMMAND --flagA=123 --flagB=xyz
```

Head to [Step 2]() to prepare your Operator Service for launch.
### Docker Image
Build the latest Operator Service docker image using the below command:

```bash
docker build --pull -t stakewiselabs/v3-operator .
```

or build a specific version using the below:

```bash
docker pull europe-west4-docker.pkg.dev/stakewiselabs/public/v3-operator:v0.3.4
```

You will execute Operator Service commands using the below format (note the use of flags are optional):
```bash
docker run --restart on-failure:10 \
-v ~/.stakewise/:/data \
europe-west4-docker.pkg.dev/stakewiselabs/public/v3-operator:v0.X.X \
src/main.py COMMAND \
--flagA=123 \
--flagB=xyz
```

Head to [Step 2]() to prepare your Operator Service for launch.

### Source Files
If you are running your node on ARM, for example, you will need to build Operator Service from source. Head to the GitHub repository to find the latest version of Operator Service, download and decompress the source files. Note, you must have Python 3.10 and Poetry installed to build from source.
Install the packages required to run Operator Service using Poetry:

```bash
poetry install --only main
```

You will execute Operator Service commands from within the `V3-operator` folder using the below format (note that the use of flags is optional):

```bash
pythonpath=. poetry run python src/main.py COMMAND --flagA=123 --flagB=xyz
```

Head to [Step 2]() to prepare your Operator Service for launch.
### Kubernetes (advanced)
A separate guide runs through the set-up of Operator Service via Kubernetes, designed to run large numbers of validators (up to 10,000). Visit the Kubernetes documentation for more information.




## 2. Prepare Operator Service

In order to run Operator Service, you must first create keystores and deposit data file for your Vault's validators, and set up a hot wallet for Operator Service to handle validator registrations.

Operator Service has in-built functionality to generate all of the above, or you are free to use your preferred methods of generating keystores and deposit data file, such as via Wagyu Keygen, and your preferred tool for generating the hot wallet, such as MetaMask or MyEtherWallet.

**Note, the deposit data file must be created using the Vault contract as the withdrawal address. You can find the Vault address either via the URL bar of your Vault page or in the "Contract address" field by scrolling to the "Details" section at the bottom of the Vault page.**

The below steps walk you through this set-up using Operator Service:
### Creating mnemonic
Run the `init` command and follow the steps to set up your mnemonic used to derive validator keys. For example, if running Operator Service from Binary, you would use:
```bash
./operator init
```
```bash
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

It is possible to pass the following flags alongside `init`, for example `./operator init --network=goerli` when setting Operator Service up for a Vault on Georli network.
- `--network` - Specified network of your vault (mainnet is default).
- `--language` - Specifies the mnemonic language (english is default).
- `--vault` - Passes vault address (null is default).
- `--no-verify` - Skips mnemonic verification process.
- `--data-dir` - Path where the vault data will be placed (~/.stakewise is default).
**Note, you must store the generated mnemonic in a secure cold storage. This mnemonic is used to restore the validator keys in case the Vault will get corrupted or lost.**
### Creating validator keystores
Next, run the `create-keys` command to kickstart the deposit data and validator keystores creation process, making sure you have your newly created mnemonic to hand:
```bash
./operator create-keys
```
```bash
Enter the vault address: 0x3320a...68
Enter the number of the validator keys to generate: 10
Enter the mnemonic for generating the validator keys: pumpkin anxiety private salon inquiry ....
Creating validator keys: [####################################] 10/10
Generating deposit data JSON [####################################] 10/10
Exporting validator keystores [####################################] 10/10
Done. Generated 10 keys for 0x3320a...68 vault.
Keystores saved to /home/user/.stakewise/0x3320ad928c20187602a2b2c04eeaa813fa899468/keystores file
Deposit data saved to /home/user/.stakewise/0x3320ad928c20187602a2b2c04eeaa813fa899468/keystores/deposit_data.json file
```

It is possible to pass the following flags alongside `create-keys`:
- `--mnemonic` - The mnemonic for generating the validator keys.
- `--count` - The number of the validator keys to generate.
- `--vault` - The Vault address to generate the keystores and deposit data for.
- `--per-keystore-password` - Creates separate password file for each keystore.
- `--data-dir` - Path where the Vault data is stored (~/.stakewise is default).

**Note, remember to upload the newly generated validator keys to your consensus client. The password for your keystores is located in the passport.txt file in the keystores folder.**
### Create hot wallet
Run the `create-wallet` command to create your hot wallet using your mnemonic (note, this mnemonic can be the same as the one used to generate the validator keys, or a new mnemonic if you desire).
```bash
./operator create-wallet
```
```bash
Enter the vault address: 0x3320a...68
Enter the mnemonic for generating the wallet: pumpkin anxiety private salon inquiry ...
Done. The wallet and password saved to /home/user/.stakewise/0x3320a...68/wallet directory. The wallet address is: 0x239B...e3Cc
```
It is possible to pass the following commands alongside `create-wallet`:
- `--vault` - The vault to generate the wallet for.
- `--mnemonic` - The mnemonic for generating the wallet.
- `--data-dir` Path where the vault data is stored (~/.stakewise is default).

**Note, you must send some ETH (DAI for Gnosis) to the wallet for gas expenses. Each validator registration costs around 0.01 ETH with 30 Gwei gas price. You must keep an eye on your wallet balance, otherwise validators will stop registering if the balance falls too low.**


## 3. Upload deposit data file to Vault

Now you have created your validator keys, deposit data file, and hot wallet, you now need to upload the deposit data file to the Vault. This process connects your node to the Vault. Note, if there is more than one node operator in a Vault, you first need to merge all operator deposit data files into a single file. Details can be found [here]().
Uploading the deposit data file can be achieved either through the StakeWise UI or via Operator Service and can only be done by the [Vault Admin or Keys Manager](https://docs-v3.stakewise.io/protocol-overview-in-depth/vaults#governance-and-management).
#### StakeWise UI
1. Connect with your wallet and head to the Operate page.
2. Select the Vault you want to upload the deposit data file to.
3. In the upper right corner, click on "Settings" and open the "Deposit Data" tab
4. Upload the deposit data file either by dragging and dropping the file, or clicking to choose the file via your file browser.
5. Click Save and a transaction will be created to sign using your wallet. The Vault's deposit data file will be uploaded when the transaction is confirmed on the network.

Head to [step 4]() to start Operator Service.

#### Operator Service
Run the following command and enter the Vault address when prompted:
```bash
./operator get-validators-root
```
Note, you can pass the below variables with `get-validators-root` if you are not using the default path storage locations:
- `--data-dir` - Path where the vault data is stored (~/.stakewise is default).
- `--deposit-data-file` - Path to the deposit data file (Vault directory is default).
- `--vault` - The vault address.
After running the command and entering your Vault address, you will be presented with the validator deposit data Merkle tree root. Make a note of this value.

```bash
The validator deposit data Merkle tree root: 0x50437ed72066c1a09ee85978f168ac7c58fbc9cd4beb7962c13e68e7faac26d7
```

Finally, upload the Merkle tree root to your Vault contract by calling `setValidatorsRoot`. Below shows the steps to do this via Etherscan, but the same can be achieved via CLI if you prefer (using [eth-cli](https://github.com/protofire/eth-cli) and `eth contract:send` for example). Note, the ABI of the contract can be found [here](https://github.com/stakewise/v3-core/blob/main/abi/IVaultValidators.json).
1. Head to your Vault's contract address page on Etherscan in your browser (e.g. replacing 0x000 with your Vault contract address: https://etherscan.io/address/0x000).
2. Select the Contract tab and then Write as Proxy.
3. Connect your wallet to Etherscan (note this must be either the Vault Admin or Keys Manager).
4. Find the `setValidatorsRoot` function and click to reveal the drop-down.
5. Enter your Merkle tree root and click Write.
6. Confirm the transaction in your wallet to finalize the deposit data upload to your Vault.

You are all set! Now it's time to run the Operator Service.



## 4. Run Operator Service

You are now ready to run the Operator Service using the `start` command, passing your Vault address and both consensus and execution endpoints as flags. For example, when running from binary:
```bash
./operator start --vault=0x000... --consensus-endpoints=http://localhost:5052 --execution-endpoints=http://localhost:8545
```
or from source:
```bash
PYTHONPATH=. poetry run python src/main.py start \
--vault=0x000... \
--consensus-endpoints=http://localhost:5052 \
--execution-endpoints=http://localhost:8545
```
For docker, you first need to mount the folder containing validator keystores and deposit data file generated in step 2 into the docker container. You then need to also include the `--data-dir` flag alongside the `start` command as per the below:
```bash
docker run --restart on-failure:10 \
-v ~/.stakewise/:/data \
europe-west4-docker.pkg.dev/stakewiselabs/public/v3-operator:v0.3.4 \
src/main.py start \
--vault=0x3320ad928c20187602a2b2c04eeaa813fa899468 \
--data-dir=/data \
--consensus-endpoints=http://localhost:5052 \
--execution-endpoints=http://localhost:8545
```
Note, if you did not create your mnemonic using Operator Service, you will need to add the following flags to direct Operator Service to the private key of your hot wallet:
- --hot-wallet-file - path to the password-protected *.txt* file containing your hot wallet private key.
- --hot-wallet-password-file - path to a *.txt* file containing the password to open the protected hot wallet private key file.
Alternatively, an environment file can be created to remove the need for using CLI flags when starting Operator Service. More information can be found [here]().
If using docker, a docker compose file is an option if you wish to simply call `docker run` without adding all the flags manually. `docker-compose.yml` is included in the docker build, edit the file according to your setup using the below command:
```bash
docker-compose up
```

**Congratulations, you should now have Operator Service up and running and ready to trigger validator registrations within your Vault!**














# V3 Operator commands

Operator Service has many different commands that are not mandatory but might come in handy:

- [Validators voluntary exit]()
- [Update Vault state (Harvest Vault)]()
- [Update Vault deposit data file]()
- [Merge deposit data files from multiple operators]()
- [Recover validator keystores]()
- [Remote Postgres database (advanced)]()


### Validators voluntary exit

Enter the below command to kickstart the voluntary exit process of all your node's validators within a specific Vault:
```bash
./operator validators-exit
```
Follow the steps, confirming your consensus node endpoint, Vault address, and the validator indexes to exit.
```bash
Enter the comma separated list of API endpoints for consensus nodes: https://example.com
Enter your vault address: 0x3320ad928c20187602a2b2c04eeaa813fa899468
Are you sure you want to exit 3 validators with indexes: 513571, 513572, 513861? [y/N]: y
Validators 513571, 513572, 513861 exits successfully initiated
```
There are a variety of variables that can be passed alongside `validators-exit` to customize its function, such as if you wish to only exit one validator in a Vault. They are detailed as follows:
- `--network` - The network of your vault (ethereum by default).
- `--vault` - Your vault address.
- `--consensus-endpoints` - Comma separated list of API endpoints for consensus nodes.
- `--count` - The number of validators to exit (all active vault validators by default).
- `--data-dir` - Path where the vault data is stored. Default is ~/.stakewise.
- `--remote-signer-url` - URL to the remote signer instance.
- `--hashi-vault-url` - URL to the remote hashi vault instance.
- `--hashi-vault-token` - Token when authenticating with hashi vault.
- `--hashi-vault-key-path` - Key path in hashi vault K/V engine holding signing secrets.
- `--verbose` - Enable debug mode (false by default).


### Update Vault state (Harvest Vault)

Updating the *Vault state* distributes the Vault fee to the Vault fee address and updates each staker's position. If an ERC-20 token was chosen during Vault creation, the Vault specific ERC-20 reprices based on the rewards/penalties since the previous update and the Vault fees are distributed in newly minted ERC-20 tokens.

By default, each *Vault state* gets updated whenever a user interacts with the Vault (deposit, withdraw, etc.), with a 12 hour cooldown. Vault state can also be updated by the Vault operator(s) by passing the `--harvest-vault` flag to the Operator Service `start` command. Harvest occurs every 24 hours and the gas fees are paid by the hot wallet linked to the Operator Service.

Harvesting the Vault rewards simplifies the contract calls to the Vault contract and reduces the gas fees for stakers, for example, the Vault does not need to sync rewards before calling deposit when a user stakes.

### Update Vault deposit data file

Note, uploading a new deposit data file will overwrite the existing file and consequently overwrite previously un-used validator keys. The can be done at any point, but only by the Vault Admin or Keys Manager.
Run the following command and enter the Vault address when prompted:
```bash
./operator get-validators-root
```
Note, you can pass the below variables with `get-validators-root` if you are not using the default path storage locations:
- `--data-dir` - Path where the vault data is stored (~/.stakewise is default).
- `--deposit-data-file` - Path to the deposit data file (Vault directory is default).
- `--vault` - The vault address.

After running the command and entering your Vault address, you will be presented with the validator deposit data Merkle tree root. Make a note of this value.

```bash
The validator deposit data Merkle tree root: 0x50437ed72066c1a09ee85978f168ac7c58fbc9cd4beb7962c13e68e7faac26d7
```

Finally, upload the Merkle tree root to your Vault contract by calling `setValidatorsRoot`. Below shows the steps to do this via Etherscan, but the same can be achieved via CLI if you prefer (using [eth-cli](https://github.com/protofire/eth-cli) and `eth contract:send` for example). Note, the ABI of the contract can be found [here](https://github.com/stakewise/v3-core/blob/main/abi/IVaultValidators.json).
1. Head to your Vault's contract address page on Etherscan in your browser (e.g. replacing 0x000 with your Vault contract address: https://etherscan.io/address/0x000).
2. Select the Contract tab and then Write as Proxy.
3. Connect your wallet to Etherscan (note this must be either the Vault Admin or Keys Manager).
4. Find the `setValidatorsRoot` function and click to reveal the drop-down.
5. Enter your Merkle tree root and click Write.
6. Confirm the transaction in your wallet to finalize the deposit data upload to your Vault.

You are all set! Now it's time to run the Operator Service.


### Merge deposit data files from multiple operators

Use the following command:
`./operator merge-deposit-data`

### Recover validator keystores

Note, for security purposes, make sure to protect your mnemonic as it can be used to generate your validator keys. Always verify the network and endpoints before running the below command to recover your validator keys.
``` bash
./operator recover
```
```bash
Enter the mnemonic for generating the validator keys: [Your Mnemonic Here]
Enter your vault address: 0x3320ad928c20187602a2b2c04eeaa813fa899468
Enter comma separated list of API endpoints for execution nodes: https://example.com
Enter comma separated list of API endpoints for consensus nodes: https://example.com
Enter the network name: goerli
Found 24 validators, recovering...
Generating keystores [####################################] 100%
Keystores for vault {vault} successfully recovered to {keystores_dir}
```
You can run the following variables alongside the `recover` command:
- `--data-dir` - Path where the Vault data will be placed (~/.stakewise is default).
- `--per-keystore-password` - Creates separate password file for each keystore.
- `--mnemonic` - The mnemonic for generating the validator keys.
- `--vault` - The vault address.
- `--execution-endpoints` - Comma separated list of API endpoints for execution nodes.
- `--consensus-endpoints` - Comma separated list of API endpoints for consensus nodes.
- `--network` - The network of your vault (mainnet is default).

### Remote Postgres database (advanced)

This feature is only used when running via [Kubernetes and web3signer](https://github.com/stakewise/helm-charts) (advanced), storing encrypted validator keys and shares in a remote database.
The [web3signer helm chart](https://github.com/stakewise/helm-charts/tree/main/charts/web3signer) pulls the private keys and decrypts them on start. The [validator pods](https://github.com/stakewise/helm-charts/tree/main/charts/validators) use the web3signer service to sign blocks and fetch the public keys they're validating for from the DB. The [operator chart](https://github.com/stakewise/helm-charts/tree/main/charts/v3-operator) pulls the config from the DB and uses web3signer to sign exit messages. Follow the steps below to get set up:

#### 1) Setup Postgres DB
The command creates tables and generates encryption key for the database:
```bash
./v3-operator remote-db \
--db-url=postgresql://postgres:postgres@localhost/operator \
--vault=0x8189aF89A7718C1baB5628399FC0ba50C6949bCc \
setup
Successfully configured remote database.
Encryption key: D/6CbpJen3J0ue0tWcd+d4KKHpT4kaSz3IzG5jz5LFI=
NB! You must store your encryption in a secure cold storage!
```

**NB! You must store the generated encryption key in a secure cold storage. You would have to re-do the setup if you lose it.**

#### 2) Load keystores to the remote DB
The command loads encrypted keystores and operator config to the remote DB:
```bash
./v3-operator remote-db \
--db-url=postgresql://postgres:postgres@localhost/operator \
--vault=0x8189aF89A7718C1baB5628399FC0ba50C6949bCc \
upload-keypairs \
--encrypt-key=D/6CbpJen3J0ue0tWcd+d4KKHpT4kaSz3IzG5jz5LFI= \
--execution-endpoints=http://localhost:8545
Loading keystores from /Users/user/.stakewise/0x8189af89a7718c1bab5628399fc0ba50c6949bcc/keystores...
Fetching oracles config...
Calculating and encrypting shares for 10000 keystores...
Uploading updates to the remote db...
Successfully uploaded keypairs and shares for the 0x8189aF89A7718C1baB5628399FC0ba50C6949bCc vault.
```

#### 3) Sync keystores to the web3signer
The command syncs encrypted keystores to the web3signer:
```bash
./v3-operator remote-db \
--db-url=postgresql://postgres:postgres@localhost/operator \
--vault=0x8189aF89A7718C1baB5628399FC0ba50C6949bCc \
--network=mainnet \
setup-web3signer \
--encrypt-key=D/6CbpJen3J0ue0tWcd+d4KKHpT4kaSz3IzG5jz5LFI= \
--output-dir=./web3signer
Fetching keypairs from the remote db...
Decrypting 120000 keystores...
Saving 120000 private keys to web3signer...
Successfully retrieved web3signer private keys from the database.
```

#### 4) Sync web3signer configs for the validators
The command syncs web3signer config for every validator:
```bash
./v3-operator remote-db \
--db-url=postgresql://postgres:postgres@localhost/operator \
--vault=0x8189aF89A7718C1baB5628399FC0ba50C6949bCc \
--network=mainnet \
setup-validator \
--validator-index=0 \
--total-validators=10 \
--web3signer-endpoint=http://localhost:9000 \
--fee-recipient=0xb793c3D2Cec1d0F35fF88BCA7655B88A44669e4B \
--output-dir=./validator0
Generated configs with 1000 keys for validator with index 0.
Validator definitions for Lighthouse saved to validator0/validator_definitions.yml file.
Signer keys for Teku\Prysm saved to validator0/signer_keys.yml file.
Proposer config for Teku\Prysm saved to validator0/proposer_config.json file.
Successfully created validator configuration files.
```

#### 5) Sync configs for the operator
The command syncs web3signer config and deposit data for the operator:
```bash
./v3-operator remote-db \
--db-url=postgresql://postgres:postgres@localhost/operator \
--vault=0x8189aF89A7718C1baB5628399FC0ba50C6949bCc \
--network=mainnet \
setup-operator
Operator remote signer configuration saved to /Users/user/.stakewise/0x8189af89a7718c1bab5628399fc0ba50c6949bcc/remote_signer_config.json file.
Operator deposit data saved to /Users/user/.stakewise/0x8189af89a7718c1bab5628399fc0ba50c6949bcc/deposit_data.json file.
Successfully created operator configuration file.
```
By default, the config will be created in the vault directory, but you can override it by providing `--output-dir`.


















# Optional Extras

- [Environment variables]()
- [Monitoring Operator with Prometheus]()
- [Remote Signer]()
- [Hashi Vault]()

### Environment variables

Operator Service can be configured via environment variables instead of CLI flags. Copy [this example file](https://github.com/stakewise/v3-operator/blob/master/.env.example) and save it as `.env`. Run through the file, adjusting as and where necessary based on your node configuration.

Remember to load the environment variables before running Operator Service, for example:
```bash
export $(grep -v '^#' .env | xargs)
```

You can check the environment variables are set and loaded correctly by running `env`.


### Monitoring Operator with Prometheus

Operator Service supports monitoring using Prometheus by providing a `/metrics` endpoint that Prometheus can scrape to gather various metrics.
#### Prerequisites
1. Operator Service up and running.
2. [Prometheus server](https://prometheus.io/) installed and running.
3. Basic knowledge of how to configure Prometheus targets.
4. [Grafana Dashboard](https://grafana.com/grafana/dashboards/19060-v3-operator/) for `v3-operator` installed and running.
#### Setup Operator Service for monitoring
Operator Service provides the flexibility to define the host and port for the metrics endpoint via environment variables. The endpoint is `http://[METRICS_HOST]:[METRICS_PORT]/metrics`, where:
- `ENABLE_METRICS`: This defines whether the metrics endpoint should be enabled or not. By default, it is set to false.
- `METRICS_HOST`: This defines the hostname or IP on which the metrics endpoint will be available.
- `METRICS_PORT`: This defines the port on which the metrics endpoint will be available.

Ensure that these environment variables are set as per your requirements, for example, http://0.0.0.0:9100/metrics would be set as:
```bash
export ENABLE_METRICS=true
export METRICS_HOST=0.0.0.0
export METRICS_PORT=9100
```
You can also specify these parameters by providing `--enable-metrics`, `--metrics-port` and `--metrics-host` flags to the `start` command of Operator Service.
#### Configure Prometheus
To monitor Operator Service, you will need to configure Prometheus to scrape metrics from the exposed `/metrics` endpoint.
Add the following job configuration in your Prometheus configuration file (`prometheus.yml`):
```bash
scrape_configs:
- job_name: 'operator'
scrape_interval: 30s
static_configs:
- targets: [ '<METRICS_HOST>:<METRICS_PORT>' ]
```
Replace `<METRICS_HOST>` and `<METRICS_PORT>` with the values you've set in Operator Service. This configuration tells Prometheus to scrape metrics from Operator Service every 30 seconds.
#### Configuring Grafana
Head to your Grafana login screen and Login. Move your mouse over the gear icon at the bottom left of the left menu bar and a menu will pop-up — choose Data Sources. Select Prometheus and enter your endpoint. Click Save & Test to finalize the set-up.



### Remote signer

This command will split up the private keys in the keystores directory into private key shares. The resulting private key shares are then imported to the remote signer. Local keystores are removed as a result of this command since they no longer need to be present.
Run the below command, adjusting the vault address and remote signer url based on your set-up:
```bash
./operator remote-signer-setup \
--vault=0x0000 \
--remote-signer-url=http://signer:9000
```
```bash
Successfully generated 11 key shares for 1 private key(s)!
Successfully imported 11 key shares into remote signer.
Removed keystores from local filesystem.
Done. Successfully configured operator to use remote signer for 1 public key(s)!
```
You can run the following variables alongside the `remote-signer-setup` command:
- `--vault` - The vault address.
- `--remote-signer-url` - The base URL of the remote signer, e.g. http://signer:9000
- `--remove-existing-keys` - Include this flag to remove any keys present in the signer that are not needed by Operator Service. Can be used to remove outdated keyshares from the remote signer when the set of Oracles changes, see note below.
- `--data-dir` - Path where the vault data is stored (~/.stakewise is default).
- `--keystores-dir` - The directory with validator keys in the EIP-2335 standard.
- `--execution-endpoints` - Comma separated list of API endpoints for execution nodes.
- `--verbose` - Enable debug mode (false is default).

Note, you will need to run this command every time the Oracle set changes, or the threshold needed to recover exit signatures (`exit_signature_recover_threshold`) changes.
### Running Operator Service when using remote signer
Provide Operator Service with the URL to your remote signer instance using the `--remote-signer-url` flag:
```bash
./operator start --remote-signer-url=http://remote-signer:9000 ...
```
You should see a message similar to this one after starting the operator:
```bash
Using remote signer at http://remote-signer:9000 for 10 public keys
```
### Regenerate key shares
In order to regenerate key shares, make sure to adjust the `mnemonic_next_index` value in the vault config.json to 0, then run the `create-keys` command, generating the full keystores for all your validators.
Next, run the `remote-signer-setup` command to regenerate and import the new key shares for all your validators into the remote signer. You can remove the previously generated private key shares from the remote signer, they will not be used anymore. This can optionally be done by the setup command automatically by using the `--remove-existing-keys` flag.



### Hashi Vault

Operator Service supports loading signing keys from a remote [Hashi Vault](https://github.com/hashicorp/vault) instance, avoiding storage of keystores on the filesystem. This approach is best suited for node operators who already have most Operator Service functionality implemented in their systems, and only need it for validator registration or pooling support. Regular users should only employ this functionality on their own risk, if they already manage a deployment of hashi vault.
Currently there are two commands that support loading signing keys: `start` and `vaidators-exit`, user must provide hashi vault instance URL, authentication token, and secret path in K/V engine. The internal structure of the secret must resemble the following json:
```bash
{
"pubkey1": "privkey1",
"pubkey2": "privkey2",
...
}
```
Note, public and private signing keys must be stored in hex form, with or without 0x prefix.
After loading keys from hashi vault, operator behaves in the same way as if it had loaded them from keystores, no additional operations needed to support the integration.
Passing following options to `start` command will enable loading validator signing keys from remote a [Hashi Vault](https://github.com/hashicorp/vault). Make sure keystores directory is empty before running this command, otherwise operator will use local keystores.
- `--hashi-vault-url` - URL to the remote hashi vault instance
- `--hashi-vault-token` - Token for use when authenticating with hashi vault
- `--hashi-vault-key-path` - Key path in hashi vault K/V engine holding signing secrets








# Contacts

- Dmitri Tsumak - <dmitri@stakewise.io>
- Alexander Sysoev - <alexander@stakewise.io>
- Evgeny Gusarov - <evgeny@stakewise.io>



