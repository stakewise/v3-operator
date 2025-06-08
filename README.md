# StakeWise V3 Operator

1. [What is V3 Operator?](#what-is-v3-operator)
2. [Prerequisites](#prerequisites)
   1. [Execution client](#execution-node)
   2. [Consensus client](#consensus-node)
   3. [Vault](#vault)
3. [Installation](#installation)
   1. [Binary](#binary)
   2. [Install Script](#install-script-linux-and-macos)
   3. [Docker Image](#docker-image)
   4. [Source Files](#source-files)
   5. [Kubernetes (advanced)](#kubernetes-advanced)
4. [Usage](#usage)
   1. [Step 1. Create mnemonic](#step-1-create-mnemonic)
   2. [Step 2. Create validator keys](#step-2-create-validator-keys)
   3. [Step 3. Create hot wallet](#step-3-create-hot-wallet)
   4. [Step 4. Setup validators manager role for vaults](#step-4-setup-validators-manager-role-for-vaults)
   5. [Step 5. Start Operator Service](#step-5-start-operator-service)
5. [Extra commands](#extra-commands)
   1. [Add validator keys to Vault](#add-validator-keys-to-vault)
   2. [Validators voluntary exit](#validators-voluntary-exit)
   3. [Update Vault state (Harvest Vault)](#update-vault-state-harvest-vault)
   4. [Recover validator keystores](#recover-validator-keystores)
   5. [Max gas fee](#max-gas-fee)
   6. [Reduce Operator Service CPU load](#reduce-operator-service-cpu-load)
   7. [Self report to Rated Network](#rated-self-report-network)
   8. [Export validators file](#export-validators-file)
6. [Contacts](#contacts)

## What is V3 Operator?

StakeWise Operator is a service that StakeWise Vault operators must run. It is responsible for performing the following
tasks:

### Validator registration

The Operator periodically checks whether Vault has accumulated enough assets for registering new validator(s) and sends
a registration transaction to the Vault.

The validator registration process consists of the following steps:

1. Check whether Vault has accumulated enough assets to register a validator (e.g., 32 ETH for Ethereum)
2. Get the next free validator public key from the `validators.txt` file attached to the Operator. The validators are
   registered in the same order as specified in the `validators.txt` file.
3. Obtain BLS signature for exit message using local keystores or remote signer.
4. Share the exit signature of the validator with StakeWise Oracles:
   1. Using [Shamir's secret sharing](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing), split
      validator's BLS signature. The number of shares is equal to the number of oracles.
   2. Encrypt exit signatures with oracles' public keys.
   3. Send encrypted exit signatures to all the oracles and receive registration signatures from them.
5. Send transaction to Vault contract to register the validator.

### Exit signatures rotation

Exit signatures from the previous section can become invalid if the oracles' set changes. For example, if oracles'
private key gets compromised, the DAO will have to propose an update of the oracles set that will trigger exit signature
rotation.
The Operator periodically checks active validators of the Vault and if some exit signatures become outdated, the
Operator will submit a signature update transaction to the Vault.

### Vault state update (optional)

The oracles periodically submit consensus rewards of all the vaults to the Keeper contract.
By default, every vault pulls these updates on the user interaction with the vault (deposit, withdraw, etc.), but it
also can be done by the vault Operator by passing the `--harvest-vault` flag to the `start` command. Harvesting vault
rewards simplifies calls to the vault contracts, e.g., you don't need to sync rewards before calling deposit.

## Prerequisites

### Execution node

Any execution client that supports [ETH Execution API specification](https://ethereum.github.io/execution-apis/api-documentation/) can be used:

- [Nethermind](https://launchpad.ethereum.org/en/nethermind) (Ethereum, Gnosis)
- [Besu](https://launchpad.ethereum.org/en/besu) (Ethereum)
- [Erigon](https://launchpad.ethereum.org/en/erigon) (Ethereum, Gnosis)
- [Geth](https://launchpad.ethereum.org/en/geth) (Ethereum)

### Consensus node

Any consensus client that supports [ETH Beacon Node API specification](https://ethereum.github.io/beacon-APIs/#/) can be used:

- [Lighthouse](https://launchpad.ethereum.org/en/lighthouse) (Ethereum, Gnosis)
- [Nimbus](https://launchpad.ethereum.org/en/nimbus) (Ethereum, Gnosis)
- [Prysm](https://launchpad.ethereum.org/en/prysm) (Ethereum)
- [Teku](https://launchpad.ethereum.org/en/teku) (Ethereum, Gnosis)
- [Lodestar](https://launchpad.ethereum.org/en/lodestar) (Ethereum, Gnosis)

### Vault

You must have a deployed Vault. You can create a new Vault or use an existing one.
To create a new Vault:

1. Go to [Operate page](https://app.stakewise.io/operate).
2. Connect with your wallet in upper right corner, then click on "Create Vault".
3. Process vault setup step by step.
4. Once vault is deployed go to its page.

**You can find the vault address either in the URL bar or in the "Contract address" field by scrolling to the "Details"
at
the bottom of the page. The vault address is used in the following sections.**

## Installation

Operator Service can be run via a binary, docker image, deployed on a Kubernetes cluster using the
Operator Helm Chart, or built from source. Decide on your preferred method and follow the respective instructions below.

### Binary

Head to the [releases page](https://github.com/stakewise/v3-operator/releases) to find the latest version of Operator
Service. Identify the binary file specific to your
node hardware, download and decompress it.

You will execute Operator Service commands from within the `v3-operator` folder using the below format (note that the
use of flags is optional):

```bash
./operator COMMAND --flagA=123 --flagB=xyz
```

Head to [Usage](#usage) to launch your Operator service.

### Install script (Linux and macOS)

To install a binary for the latest release, run:

```bash
curl -sSfL https://raw.githubusercontent.com/stakewise/v3-operator/master/scripts/install.sh | sh -s
```

The binary will be installed inside the ~/bin directory. Add the binary to your path:

```bash
export PATH=$PATH:~/bin
```

If you want to install a specific version to a custom location, run:

```bash
curl -sSfL https://raw.githubusercontent.com/stakewise/v3-operator/master/scripts/install.sh | sh -s -- -b <custom_location> vX.X.X
```

You will execute Operator Service commands using the below format (note that the use of flags is optional):

```bash
operator COMMAND --flagA=123 --flagB=xyz
```

Head to [Usage](#usage) to launch your Operator service.

### Docker Image

Pull the latest docker Operator docker image:

```bash
docker pull europe-west4-docker.pkg.dev/stakewiselabs/public/v3-operator:v3.1.6
```

You can also build the docker image from source by cloning this repo and executing the following command from within
the `v3-operator` folder:

```bash
docker build --pull -t europe-west4-docker.pkg.dev/stakewiselabs/public/v3-operator:v3.1.6 .
```

You will execute Operator Service commands using the format below (note the use of flags are optional):

```bash
docker run --rm -ti \
-u $(id -u):$(id -g) \
-v ~/.stakewise/:/data \
europe-west4-docker.pkg.dev/stakewiselabs/public/v3-operator:v3.1.6 \
src/main.py COMMAND \
--flagA=123 \
--flagB=xyz
```

Head to [Usage](#usage) to launch your Operator service.

### Source Files

Build requirements:

- [Python 3.10+](https://www.python.org/downloads/)
- [Poetry](https://python-poetry.org/docs/)

Clone this repo and install dependencies by executing the following command from within the `v3-operator` folder:

```bash
poetry install --only main
```

You will execute Operator Service commands from within the `v3-operator` folder using the below format (note that the
use of flags is optional):

```bash
PYTHONPATH=. poetry run python src/main.py COMMAND --flagA=123 --flagB=xyz
```

Head to [Usage](#usage) to launch your Operator service.

### Kubernetes (advanced)

A separate guide runs through the set-up of Operator Service via Kubernetes, designed to run large numbers of
validators (up to 10,000). Visit
the [Kubernetes setup](https://docs.stakewise.io/for-operators/kubernetes-staking-setup) for more details.

## Usage

To run the Operator Service, you must first create keystores and a file containing the list of available validator public keys for your Vault. You must also
set up a hot wallet for Operator Service to handle validator registrations.

The Operator Service includes built-in functionality to generate all of the above.
Alternatively, you may use your preferred methods to generate keystores (e.g., [Wagyu Keygen](https://github.com/stake-house/wagyu-key-gen))
and create the hot wallet (e.g., [MetaMask](https://metamask.io/) or [MyEtherWallet](https://help.myetherwallet.com/en/articles/6512619-using-mew-offline-current-mew-version-6)).
If you choose to use your own methods, you will need to generate the public key file using the `export-public-keys` command.

The below steps walk you through this set-up using Operator Service:

### Step 1. Create mnemonic

Run the `init` command and follow the steps to set up your mnemonic used to derive validator keys. For example, if
running Operator Service from binary, you would use:

```bash
./operator init
```

```text
Enter the network name (mainnet, hoodi, gnosis, chiado) [mainnet]:
Choose your mnemonic language (chinese_simplified, chinese_traditional, czech, english, italian, korean, portuguese, spanish) [english]:
This is your seed phrase. Write it down and store it safely, it is the ONLY way to recover your validator keys.

pumpkin anxiety private salon inquiry ....


Press any key when you have written down your mnemonic.

Please type your mnemonic (separated by spaces) to confirm you have written it down

: pumpkin anxiety private salon inquiry ....

done.
Successfully initialized configuration for StakeWise Operator
```

### Step 2. Create validator keys
Next, run the `create-keys` command to derive validator keystores from the mnemonic:

```bash
./operator create-keys
```

```text
Enter the number of the validator keys to generate: 10
Enter the mnemonic for generating the validator keys: pumpkin anxiety private salon inquiry ....
Creating validator keys:    [####################################]  10/10
Exporting validator keystores    [####################################]  10/10

Done. Generated 10 keys for StakeWise Operator.
Keystores saved to /home/user/.stakewise/keystores file
Validator public keys saved to /home/user/.stakewise/validators.txt file
```

You may not want the Operator service to have direct access to the validator keys. Validator keystores do not need to be
present directly in the Operator. You can check
the [remote signer](https://docs.stakewise.io/for-operators/operator-service/running-with-remote-signer)
or [Hashicorp Vault](https://docs.stakewise.io/for-operators/operator-service/running-with-hashi-vault) guides on how to
run Operator Service with them.

**Remember to upload the newly generated validator keys to the validator(s). For that, please follow a guide for your
consensus client. The password for your keystores is located in the `password.txt` file in the keystores folder.**

### Step 3. Create hot wallet

Run the `create-wallet` command to create your hot wallet using your mnemonic (note, this mnemonic can be the same as
the one used to generate the validator keys, or a new mnemonic if you desire).

```bash
./operator create-wallet
```

```text
Enter the mnemonic for generating the wallet: pumpkin anxiety private salon inquiry ...
Done. The wallet and password saved to /home/user/.stakewise/wallet directory. The wallet address is: 0x239B...e3Cc
```

**Note, you must send some ETH (xDAI for Gnosis) to the wallet for gas expenses. Each validator registration costs around
0.01 ETH with 30 Gwei gas price. You must keep an eye on your wallet balance, otherwise validators will stop registering
if the balance falls too low.**

### Step 4. Setup validators manager role

You must assign the Validators Manager role to the wallet address created in the previous step.
This setup can be completed via the StakeWise UI and must be performed by the [Vault Admin](https://docs-v3.stakewise.io/protocol-overview-in-depth/vaults#governance-and-management).

#### StakeWise UI

1. Connect with your wallet and head to the Operate page.
2. Select the Vault for which you want to change the validators manager role.
3. In the upper right corner, click on "Settings" and open the "Roles" tab. The "Settings" button is only visible
   to the Vault Admin or Validators Manager.
4. Enter the wallet address in the "Validators manager" field.
5. Click "Save" to create a transaction that you will need to sign with your wallet. The Validators Manager role will be
   updated once the transaction is confirmed on the network.

You are all set! Now it's time to run the Operator Service.

### Step 5. Start Operator Service

You are ready to run the Operator Service using the `start` command, optionally passing your Vault address and consensus
and execution endpoints as flags.

If you **did not** use Operator Service to generate hot wallet, you will need to add the following flags:

- `--hot-wallet-file` - path to the password-protected _.txt_ file containing your hot wallet private key.
- `--hot-wallet-password-file` - path to a _.txt_ file containing the password to open the protected hot wallet private
  key file.

If you **did not** use Operator Service to generate validator keys, you will need to add the following flag:

- `--keystores-dir` - The directory with validator keys in the EIP-2335 standard. The folder must contain either a
  single `password.txt` password file for all the keystores or separate password files for each keystore with the same
  name as keystore, but ending with `.txt`. For example, `keystore1.json`, `keystore1.txt`, etc.

#### Using binary

You can start the Operator service using binary with the following command:

```bash
./operator start --vaults=0x000...,0x111... --consensus-endpoints=http://localhost:5052 --execution-endpoints=http://localhost:8545
```

#### Using docker

For docker, you first need to mount the folder containing validator keystores and deposit data file generated
into the docker container. You then need to also include the `--data-dir` flag alongside the `start` command as per the
below:

```bash
docker run --restart on-failure:10 \
-u $(id -u):$(id -g) \
-v ~/.stakewise/:/data \
europe-west4-docker.pkg.dev/stakewiselabs/public/v3-operator:v3.1.6 \
src/main.py start \
--vaults=0x3320ad928c20187602a2b2c04eeaa813fa899468 \
--data-dir=/data \
--consensus-endpoints=http://localhost:5052 \
--execution-endpoints=http://localhost:8545
```

#### Using Source Files

```bash
PYTHONPATH=. poetry run python src/main.py start \
--vaults=0x000... \
--consensus-endpoints=http://localhost:5052 \
--execution-endpoints=http://localhost:8545
```

**Congratulations, you should now have Operator Service up and running and ready to trigger validator registrations
within your Vault!**

## Extra commands

Operator Service has many different commands that are not mandatory but might come in handy:

- [Validators voluntary exit](#validators-voluntary-exit)
- [Update Vault state (Harvest Vault)](#update-vault-state-harvest-vault)
- [Add validator keys to Vault](#add-validator-keys-to-vault)
- [Recover validator keystores](#recover-validator-keystores)
- [Self report to Rated Network](#rated-self-report-network)

### Add validator keys to Vault

You can always add more validator keys to your Vault. For that, you need to generate new validator keys
as described in [Step 2. Create validator keys](#step-2-create-validator-keys).

### Validators voluntary exit

The validator exits are handled by oracles, but in case you want to force trigger exit your
validators, you can run the following command:

```bash
./operator validators-exit
```

Follow the steps, confirming your consensus node endpoint, Vault address, and the validator indexes to exit.

```text
Enter the comma separated list of API endpoints for consensus nodes: https://example.com
Enter your vault address: 0x3320ad928c20187602a2b2c04eeaa813fa899468
Are you sure you want to exit 3 validators with indexes: 513571, 513572, 513861? [y/N]: y
Validators 513571, 513572, 513861 exits successfully initiated
```

### Update Vault state (Harvest Vault)

Updating the _Vault state_ distributes the Vault fee to the Vault fee address and updates each staker's position. If an
ERC-20 token was chosen during Vault creation, the Vault specific ERC-20 reprices based on the rewards/penalties since
the previous update and the Vault fees are distributed in newly minted ERC-20 tokens.

By default, each _Vault state_ gets updated whenever a user interacts with the Vault (deposit, withdraw, etc.), with a
12 hours cooldown. Vault state can also be updated by the Vault Operator(s) by passing the `--harvest-vault` flag to the
Operator Service `start` command. Harvest occurs every 12 hours and the gas fees are paid by the hot wallet linked to
the Operator Service.

Harvesting the Vault rewards simplifies the contract calls to the Vault contract and reduces the gas fees for stakers,
for example, the Vault does not need to sync rewards before calling deposit when a user stakes.

### Recover validator keystores

You can recover validator keystores that are active.
**Make sure there are no validators running with recovered validator keystores and 2 epochs have passed, otherwise you
can get slashed. For security purposes, make sure to protect your mnemonic as it can be used to generate your validator
keys.**

```bash
./operator recover
```

```text
Enter the mnemonic for generating the validator keys: [Your Mnemonic Here]
Enter your vault address: 0x3320ad928c20187602a2b2c04eeaa813fa899468
Enter comma separated list of API endpoints for execution nodes: https://example.com
Enter comma separated list of API endpoints for consensus nodes: https://example.com
Enter the network name: goerli
Found 24 validators, recovering...
Generating keystores [####################################] 100%
Keystores for vault {vault} successfully recovered to {keystores_dir}
```

### Max gas fee

To mitigate excessive gas costs, operators can pass the `--max-fee-per-gas-wei` flag when starting Operator Service (or
configure this variable via Environment Variables) to set the maximum base fee they are happy to pay for both validator
registrations and Vault harvests (if Operator is started using the `--harvest-vault` flag).

### Reduce Operator Service CPU load

`--pool-size` can be passed as a flag with both start and create-keys commands. This flag defines the number of CPU
cores that are used to both load keystores and create keystores. By default, Operator Service will use 100% of the CPU
cores.
Setting `--pool-size` to (number of CPU cores) / 2 is a safe way to ensure that Operator Service does not take up too
much CPU load and impact node performance during the creation and loading of keystores.

### Rated self report

This command allows you to self-report your validator keys to the Rated Network, ensuring that your validator set is tracked and updated on the Rated Explorer.

To use the `rated-self-report` command, you will need to provide the following parameters:

- `--data-dir`: Path where the vault data will be placed. Default is ~/.stakewise.
- `--vaults`:  The comma separated list of your vault addresses.
- `--network`: The network of your vault (e.g., mainnet, hoodi).
- `--pool-tag`: The pool name listed on the Explorer (optional).
- `--token`: OAuth token for authorization.

Here's an example of how to use the command:

```bash
python src/main.py rated-self-report --vaults <your-vault-addresses> --network <network-name> --pool-tag <pool-tag> --token <your-oauth-token> --data-dir <path-to-data-dir>
```

### Export validators file

This command fetches available public keys from local keystores and exports them to a validators.txt file.

To use the `export-public-keys` command, you can provide the following parameters:

- `--data-dir`: Path where the vault data will be placed. Default is ~/.stakewise.
- `--keystores-dir` - The directory with validator keys in the EIP-2335 standard.

Here's an example of how to use the command:

```bash
python src/main.py export-public-keys --data-dir <path-to-data-dir>
```

## Contacts

- Dmitri Tsumak - <dmitri@stakewise.io>
- Alexander Sysoev - <alexander@stakewise.io>
- Evgeny Gusarov - <evgeny@stakewise.io>
