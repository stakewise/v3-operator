import json
import os
from itertools import zip_longest

import asyncclick as click

from src.common.contrib import greenify


@click.option(
    '--deposit-data-files',
    '-d',
    required=True,
    multiple=True,
    help='Path to the deposit data file. To specify multiple deposit data files, '
    'use the -d option multiple times. Example: -d /path/to/file1 -d /path/to/file2',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
)
@click.option(
    '--output-file',
    '-m',
    required=True,
    help='Path where the merged deposit data file will be created. '
    'Specify the full path including the filename. Example: -m /path/to/merged_file.json',
    type=click.Path(exists=False, file_okay=True, dir_okay=False),
)
@click.command(
    help='Merges multiple deposit data files into one. The first validator in '
    'the merged file will be the validator from the first deposit data file, '
    'then the first validator key from the second file, etc., until all the first keys '
    'from all the deposit data files are processed. '
    'Then it continues with the second key from each file the same way.'
)
def merge_deposit_data(deposit_data_files: tuple, output_file: str) -> None:
    if len(deposit_data_files) <= 1:
        raise click.BadParameter('You must provide at least 2 deposit data files')

    if os.path.exists(output_file):
        raise click.BadParameter(f'{output_file} already exists.')

    json_data_list = []

    for file_path in deposit_data_files:
        with open(file_path, 'r', encoding='utf-8') as file:
            json_data_list.append(json.load(file))

    merged_json = []

    for elements in zip_longest(*json_data_list, fillvalue=None):
        for element in elements:
            if element is not None:
                merged_json.append(element)

    with open(output_file, 'w', encoding='utf-8') as merged_file:
        json.dump(merged_json, merged_file)

    click.echo(f'The merged deposit data file saved to {greenify(output_file)}')
