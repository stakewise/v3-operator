import unittest
from unittest.mock import patch

from click.testing import CliRunner

from src.commands.sync_validator import sync_validator

from .factories import faker


class TestSyncValidator(unittest.TestCase):
    def test_basic(self):
        fee_recipient = faker.eth_address()
        keys_count = 1000
        validator_index = 3
        total_validators = 5
        db_url = 'postgresql://username:pass@hostname/dbname'

        public_keys = [faker.eth_public_key() for x in range(keys_count)]

        runner = CliRunner()
        args = [
            '--total-validators',
            total_validators,
            '--validator-index',
            validator_index,
            '--db-url',
            db_url,
            '--web3signer-endpoint',
            'https://example.com',
            '--fee-recipient',
            fee_recipient,
            '--disable-proposal-builder',
        ]

        with runner.isolated_filesystem(), patch(
            'src.commands.sync_validator.check_db_connection'
        ), patch(
            'src.commands.sync_validator.Database.fetch_public_keys_count',
            return_value=keys_count,
        ), patch(
            'src.commands.sync_validator.Database.fetch_public_keys_by_range',
            return_value=public_keys[400:600],
        ):
            result = runner.invoke(sync_validator, args)
            assert result.exit_code == 0
            output = '''
Done. Generated configs with 200 keys for validator #3.
Validator definitions for Lighthouse saved to data/configs/validator_definitions.yml file.
Signer keys for Teku\\Prysm saved to data/configs/signer_keys.yml file.
Proposer config for Teku\\Prysm saved to data/configs/proposer_config.json file.
'''
            assert output.strip() == result.output.strip()
            validator_public_keys = public_keys[400:600]
            with open('./data/configs/validator_definitions.yml', encoding='utf-8') as f:
                s = """---"""
                for public_key in validator_public_keys:
                    s += f"""
- enabled: true
  suggested_fee_recipient: \'{fee_recipient}\'
  type: web3signer
  url: https://example.com
  voting_public_key: \'{public_key}\'"""
                s += '\n'
                assert f.read() == s

            with open('./data/configs/signer_keys.yml', encoding='utf-8') as f:
                # pylint: disable-next=line-too-long
                s = f"""validators-external-signer-public-keys: [{",".join('"' + x + '"' for x in validator_public_keys)}]"""
                ff = f.read()
                assert ff == s, (ff, s)

            with open('./data/configs/proposer_config.json', encoding='utf-8') as f:
                s = (
                    """{
    "default_config": {
        "fee_recipient": "%s",
        "builder": {
            "enabled": false
        }
    }
}"""
                    % fee_recipient
                )
                ff = f.read()

                assert ff == s, (ff, s)
