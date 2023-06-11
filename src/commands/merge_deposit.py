import json
import os
from itertools import zip_longest

import click


@click.option(
    '--deposit-data',
    '-d',
    required=True,
    multiple=True,
    help='Path to the deposit data file(s). To specify multiple deposit data files, '
    'use the -d option multiple times. Example: -d /path/to/file1 -d /path/to/file2',
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
)
@click.option(
    '--merged-file-path',
    '-m',
    required=True,
    help='Path where the merged deposit file will be created. '
    'Specify the full path including the filename. Example: -m /path/to/merged_file.json',
    type=click.Path(exists=False, file_okay=True, dir_okay=False),
)
@click.command(help='Merges multiple deposit data files into one. '
               'The merge process will take JSON elements from each input '
               'file in a round-robin manner. It starts by taking the first '
               'JSON element from each file, then the second, and so on. '
               'The merged JSON elements are written to the specified output file. '
               'If a file has fewer elements than others, the process continues with '
               'the remaining files until all elements are merged.')
def merge_deposit_data(deposit_data: tuple, merged_file_path: str) -> None:
    if len(deposit_data) <= 1:
        raise click.BadParameter('You must provide at least 2 deposit data files')

    json_data_list = []

    for file_path in deposit_data:
        with open(file_path, 'r', encoding='utf-8') as file:
            json_data_list.append(json.load(file))

    merged_json = []

    for elements in zip_longest(*json_data_list, fillvalue=None):
        for element in elements:
            if element is not None:
                merged_json.append(element)

    if os.path.exists(merged_file_path):
        raise click.BadParameter(f'{merged_file_path} already exists.')

    with open(merged_file_path, 'w', encoding='utf-8') as merged_file:
        json.dump(merged_json, merged_file)
