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
            'holesky',
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
            'holesky',
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
            '--no-verify',
            '--vault',
            vault,
            '--network',
            'holesky',
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
