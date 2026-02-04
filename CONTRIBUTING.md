# Guide for contributors

Welcome! This guide provides step-by-step instructions to help you contribute effectively to the Stakewise Operator project.

## Commit signature

Repository settings require all commits to be signed. You have to setup GPG signature locally.  See [instructions](https://docs.github.com/articles/about-gpg/).

## Installation

1. Install [poetry](https://python-poetry.org/). See the [Dockerfile](https://github.com/stakewise/v3-operator/blob/master/Dockerfile) in the project sources for the exact poetry version.
2. Check out github repo.
3. Run `poetry install --no-root`. This command will install all dependencies including dev dependencies.
4. Add project directory to `PYTHONPATH`. For example: `export PYTHONPATH=.`.

## Linting and testing

**Note:** The GitHub CI pipeline is disabled for pull requests originating from forked repositories. Therefore, you must run linters and tests locally before submitting your pull request.

1. Run linters: `black src && pre-commit run -a`
2. Run tests: `pytest`
