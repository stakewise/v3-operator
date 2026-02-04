# Guide for contributors

This guide will help you to contribute to Stakewise Operator or Oracle service.

## Commit signature

Repository settings require all commits to be signed. You have to setup GPG signature locally.  See [instructions](https://docs.github.com/articles/about-gpg/).

## Installation

1. Install [poetry](https://python-poetry.org/). See Dockerfile in project sources for exact poetry version.
2. Check out github repo.
3. Run `poetry install --no-root`. This command will install all dependencies including dev dependencies.
4. Add project directory to `PYTHONPATH`. For example: `export PYTHONPATH=`.

## Linting and testing

Github CI pipeline is disabled for pull requests from forked repositories. So you have to run linters and tests locally.

1. Run linters: `black src && pre-commit run -a`
2. Run tests: `pytest`
