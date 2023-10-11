import os

import asyncclick as click
from staking_deposit.key_handling.key_derivation.mnemonic import (
    get_mnemonic,
    reconstruct_mnemonic,
)
from staking_deposit.utils.constants import MNEMONIC_LANG_OPTIONS

WORD_LISTS_PATH = os.path.join(os.path.dirname(__file__), 'word_lists')

LANGUAGES = MNEMONIC_LANG_OPTIONS.keys()


def create_new_mnemonic(mnemonic_language: str, skip_test: bool) -> str:
    mnemonic = get_mnemonic(language=mnemonic_language, words_path=WORD_LISTS_PATH)
    if skip_test:
        click.echo(mnemonic)
        return mnemonic
    test_mnemonic = ''
    while mnemonic != test_mnemonic:
        click.clear()
        click.echo(
            'This is your seed phrase. Write it down and store it safely, '
            'it is the ONLY way to recover your validator keys.'
        )  # noqa: E501
        click.echo(f'\n\n{mnemonic}\n\n')
        click.pause('Press any key when you have written down your mnemonic.')
        click.clear()
        test_mnemonic = click.prompt(
            'Please type your mnemonic (separated by spaces) '
            'to confirm you have written it down\n\n'
        )  # noqa: E501
        test_mnemonic = test_mnemonic.lower()
    click.clear()
    click.secho(
        'done.',
        bold=True,
        fg='green',
    )
    return mnemonic


def validate_mnemonic(mnemonic) -> str:
    if reconstruct_mnemonic(mnemonic, WORD_LISTS_PATH):
        return mnemonic
    raise click.BadParameter('That is not a valid mnemonic, please check for typos.')
