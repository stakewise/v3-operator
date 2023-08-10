import json
import os
import tempfile

from click.testing import CliRunner

from src.commands.merge_deposit_data import merge_deposit_data


def test_merge_deposit_files(runner: CliRunner):
    file1_content = [
        {'id': 1, 'pubkey': '0x1'},
        {'id': 3, 'pubkey': '0x3'},
    ]
    file2_content = [
        {'id': 2, 'pubkey': '0x2'},
        {'id': 4, 'pubkey': '0x4'},
    ]

    with tempfile.NamedTemporaryFile('w', delete=False) as file1, tempfile.NamedTemporaryFile(
        'w', delete=False
    ) as file2:
        json.dump(file1_content, file1)
        json.dump(file2_content, file2)

        file1.flush()
        file2.flush()

        merged_file = _generate_temp_filepath()

        result = runner.invoke(
            merge_deposit_data,
            [
                '-d',
                file1.name,
                '-d',
                file2.name,
                '-m',
                merged_file,
            ],
        )

        assert result.exit_code == 0

        with open(merged_file, 'r', encoding='utf-8') as f:
            merged_json = json.load(f)

        expected_merged_json = [
            {'id': 1, 'pubkey': '0x1'},
            {'id': 2, 'pubkey': '0x2'},
            {'id': 3, 'pubkey': '0x3'},
            {'id': 4, 'pubkey': '0x4'},
        ]

        assert merged_json == expected_merged_json

    os.remove(file1.name)
    os.remove(file2.name)
    os.remove(merged_file)


def _generate_temp_filepath(extension=''):
    temp_dir = tempfile.gettempdir()
    temp_filename = f'{tempfile.mktemp()}{extension}'
    temp_filepath = os.path.join(temp_dir, temp_filename)

    return temp_filepath
