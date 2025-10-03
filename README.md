# StakeWise V3 Operator

[Documentation](https://docs.stakewise.io/operator/intro)

## Overview

StakeWise Operator is a service that StakeWise Vault operators must run. It is responsible for performing the following
tasks:

- Validator Registration
- Exit signatures rotation
- Withdrawals processing
- Vault State Update

And many more. Check the [Documentation](https://docs.stakewise.io/operator/intro) for details.

## Prerequisites

### Execution node

Any execution client that supports [ETH Execution API specification](https://ethereum.github.io/execution-apis/api-documentation/) can be used:

- [Nethermind](https://launchpad.ethereum.org/en/nethermind) (Ethereum, Gnosis)
- [Besu](https://launchpad.ethereum.org/en/besu) (Ethereum)
- [Erigon](https://launchpad.ethereum.org/en/erigon) (Ethereum, Gnosis)
- [Geth](https://launchpad.ethereum.org/en/geth) (Ethereum)

Built-in node management commands will simplify the process of installation and running execution and consensus nodes. Refer to the "nodes" section below for details.

### Consensus node

Any consensus client that supports [ETH Beacon Node API specification](https://ethereum.github.io/beacon-APIs/#/) can be used:

- [Lighthouse](https://launchpad.ethereum.org/en/lighthouse) (Ethereum, Gnosis)
- [Nimbus](https://launchpad.ethereum.org/en/nimbus) (Ethereum, Gnosis)
- [Prysm](https://launchpad.ethereum.org/en/prysm) (Ethereum)
- [Teku](https://launchpad.ethereum.org/en/teku) (Ethereum, Gnosis)
- [Lodestar](https://launchpad.ethereum.org/en/lodestar) (Ethereum, Gnosis)

Built-in node management commands make it easy to install and run both execution and consensus nodes. Refer to the "nodes" section below for details.

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

### Docker Image

Pull the latest docker Operator docker image:

```bash
docker pull europe-west4-docker.pkg.dev/stakewiselabs/public/v3-operator:v4.0.1
```

You can also build the docker image from source by cloning this repo and executing the following command from within
the `v3-operator` folder:

```bash
docker build --pull -t europe-west4-docker.pkg.dev/stakewiselabs/public/v3-operator:v4.0.1 .
```

You will execute Operator Service commands using the format below (note the use of flags are optional):

```bash
docker run --rm -ti \
-u $(id -u):$(id -g) \
-v ~/.stakewise/:/data \
europe-west4-docker.pkg.dev/stakewiselabs/public/v3-operator:v4.0.1 \
src/main.py COMMAND \
--flagA=123 \
--flagB=xyz
```

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

## V4 Upgrade Guide

### Pectra Upgrade Support

Ensure your vault is updated to version 5 for Ethereum network or version 3 for Gnosis network for full Pectra compatibility.

After the upgrade, validator balances are no longer limited to 32 ETH or 1 GNO. By default, the 0x02 validators are registered. To register 0x01 validators, add the flag `--validators-type=v1`. Note that funding will be disabled when using this validator type.

When replenishing validators, funds first top up existing 0x02 validators up to 2048 ETH or 64 GNO. New validators are registered once the vault accumulates another 32 ETH or 1 GNO.

To migrate 0x01 validators to 0x02, use the consolidate command (see [reference](#validators-consolidation)).

Also, partial withdrawals for compound validators are now supported. Partial withdrawals are significantly faster and more efficient than full validator exits. Even full validator exits now can be processed via execution request call.
To disable this, use the flag `--disable-withdrawals` — in this case, funds will be withdrawn via full exits using oracles.

Partial withdrawals run every 24 hours by default, processing available ETH from validators with balances exceeding 32 ETH or 1 GNO. The operator prioritizes validators with higher balances first.

If partial withdrawal capacity is insufficient or no validators have balances above 32 ETH or 1 GNO, the operator triggers a full validator exit.

If the operator does not initiate partial or full withdrawals, the oracle will automatically execute full withdrawal after 24 hours.

### Start Command

We've streamlined the launch process by separating setup flows for Hashi Vault, Web3Signer and relayers — each now has its own dedicated command.

📖 Docs: [Start Operator Service](#step-5-start-operator-service)

### No More Deposit Data File

V4 Operator no longer requires pre-uploaded deposit data for validator registration — it generates deposit data automatically during registration.

⚠ Important: To support this new flow, you must assign your operator wallet as the Validators Manager in the vault settings.
🔗 [How to Set Up Validators Manager](#step-4-setup-validators-manager-role)

### Multivault Support

The operator service can now manage multiple vaults simultaneously, reducing setup complexity for multi-vault users.

Key Changes:

- Single Wallet & Keystores – Shared across all vaults (no `--vault` flag needed for create-keys/create-wallets).
- Migration – Existing setups will auto-migrate to the new structure on first launch.
- Launch Command – Use `--vaults` with multiple addresses (e.g., `--vaults=0x1...23,0x4...56`).
- All validator keys linked to the operator will be used for every connected vault.

### Automated rewards withdrawals

It is possible to periodically withdraw rewards for the vault’s fee shareholders.
Check for more details in [Reward splitter section](#automated-withdrawals-reward-splitter)

### TL;DR – Quick Setup Checklist

#### Mandatory

- Upgrade vault to version 5 for Ethereum or version 3 for Gnosis.
- Set Validator Manager role in vault UI.

#### For Pectra

- Use consolidate command for legacy validators.

#### Per Setup Type

- Default Mode → No changes needed.
- Remote Signer → Use `start-remote-signer` command.
- Hashi Vault → Use `start-hashi-vault` command.
- Relayer → Use `start-relayer` command.

#### For Multivault

- Pass comma-separated addresses in --vaults.
- Recreate operator directory for clean migration.

#### Main parameter changes

- `--vault` → Now `--vaults` , `--vault` is deprecated.
- Removed `--deposit-data-file` parameter
- `HOT_WALLET_FILE` → renamed to `WALLET_FILE`
- `HOT_WALLET_PASSWORD_FILE` → renamed to `WALLET_PASSWORD_FILE`

## Contacts

- Dmitri Tsumak - <dmitri@stakewise.io>
- Alexander Sysoev - <alexander@stakewise.io>
- Evgeny Gusarov - <evgeny@stakewise.io>
