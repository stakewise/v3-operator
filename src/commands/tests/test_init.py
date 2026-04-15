from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner
from sw_utils.tests.factories import faker

from src.commands.init import init

mnemonic = ' '.join([faker.word().lower() for x in range(24)])


@patch('src.common.language.get_mnemonic', return_value=mnemonic)
class TestCreateMnemonic:
    def test_basic(self, mnemonic_mock, data_dir, runner: CliRunner):
        vault = faker.eth_address()
        args = [
            '--data-dir',
            str(data_dir),
            '--language',
            'english',
            '--vault',
            vault,
            '--network',
            'hoodi',
        ]
        result = runner.invoke(init, args, input=f'\n{mnemonic}\n')
        assert result.exit_code == 0
        mnemonic_mock.assert_called_once()
        assert mnemonic in result.output.strip()
        assert 'Successfully initialized configuration' in result.output.strip()

    def test_bad_verify(self, mnemonic_mock, data_dir, runner: CliRunner):
        vault = faker.eth_address()

        args = [
            '--data-dir',
            str(data_dir),
            '--language',
            'english',
            '--vault',
            vault,
            '--network',
            'hoodi',
        ]
        result = runner.invoke(init, args, input=f'\n{mnemonic} bad\n\n{mnemonic}\n')
        assert result.exit_code == 0
        mnemonic_mock.assert_called_once()
        assert mnemonic in result.output.strip()
        assert 'Successfully initialized configuration' in result.output.strip()

    def test_no_verify(self, mnemonic_mock, data_dir, runner: CliRunner):
        vault = faker.eth_address()

        args = [
            '--data-dir',
            str(data_dir),
            '--language',
            'english',
            '--vault',
            vault,
            '--no-verify',
            '--network',
            'hoodi',
        ]
        result = runner.invoke(init, args)
        assert result.exit_code == 0
        mnemonic_mock.assert_called_once()
        assert mnemonic == result.output.strip()

    def test_bad_language(self, data_dir, runner: CliRunner):
        args = ['--data-dir', str(data_dir), '--language', 'bad', '--no-verify']
        result = runner.invoke(init, args)
        assert result.exit_code == 2
        assert "Invalid value for '--language': 'bad' is not one of" in result.output.strip()

    def test_community_operator(self, mnemonic_mock, data_dir: Path, runner: CliRunner):
        operator_address = faker.eth_address()
        network = 'hoodi'
        args = [
            '--data-dir',
            str(data_dir),
            '--language',
            'english',
            '--community-operator',
            operator_address,
            '--no-verify',
            '--network',
            network,
        ]
        result = runner.invoke(init, args)
        assert result.exit_code == 0

        expected_dir = data_dir / operator_address.lower()
        assert expected_dir.is_dir()
        assert (expected_dir / 'config.json').is_file()

    def test_vault_and_community_operator_mutually_exclusive(
        self, mnemonic_mock, data_dir, runner: CliRunner
    ):
        vault = faker.eth_address()
        operator_address = faker.eth_address()
        args = [
            '--data-dir',
            str(data_dir),
            '--language',
            'english',
            '--vault',
            vault,
            '--community-operator',
            operator_address,
            '--no-verify',
            '--network',
            'hoodi',
        ]
        result = runner.invoke(init, args)
        assert result.exit_code == 1
        assert 'mutually exclusive' in result.output
