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
docker pull europe-west4-docker.pkg.dev/stakewiselabs/public/v3-operator:v4.1.6
```

You can also build the docker image from source by cloning this repo and executing the following command from within
the `v3-operator` folder:

```bash
docker build --pull -t europe-west4-docker.pkg.dev/stakewiselabs/public/v3-operator:v4.1.6 .
```

You will execute Operator Service commands using the format below (note the use of flags are optional):

```bash
docker run --rm -ti \
-u $(id -u):$(id -g) \
-v ~/.stakewise/:/data \
europe-west4-docker.pkg.dev/stakewiselabs/public/v3-operator:v4.1.6 \
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

## Contacts

- Dmitri Tsumak - <dmitri@stakewise.io>
- Alexander Sysoev - <alexander@stakewise.io>
- Evgeny Gusarov - <evgeny@stakewise.io>
