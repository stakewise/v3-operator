from click.testing import CliRunner

from src.commands.env_vars import env_vars
from src.config.env_vars import get_env_vars


class TestEnvVars:
    def test_every_variable_is_documented(self, runner: CliRunner) -> None:
        # populate the registry with the variables declared inside Settings.set()
        runner.invoke(env_vars, [])

        undocumented = [var.name for var in get_env_vars() if not var.description]
        assert not undocumented, (
            f'Environment variables without a description: {", ".join(undocumented)}. '
            f'Pass group= and description= to decouple_config so that they show up '
            f'in the env-vars command.'
        )

    def test_every_variable_is_grouped(self, runner: CliRunner) -> None:
        runner.invoke(env_vars, [])

        ungrouped = [var.name for var in get_env_vars() if var.group == 'Other']
        assert not ungrouped, f'Environment variables without a group: {", ".join(ungrouped)}'

    def test_text_output(self, runner: CliRunner) -> None:
        result = runner.invoke(env_vars, [])

        assert result.exit_code == 0
        assert 'EVENTS_BLOCKS_RANGE_INTERVAL' in result.output
        assert 'Block range size of a single eth_getLogs query' in result.output

    def test_network_dependent_default_is_not_reported_as_a_single_number(
        self, runner: CliRunner
    ) -> None:
        # the command runs against a placeholder network, so the one default
        # derived from the network must describe itself instead of resolving
        result = runner.invoke(env_vars, [])

        assert result.exit_code == 0
        assert 'Default: 12 hours of blocks (3600 on mainnet, 8640 on gnosis)' in result.output

    def test_markdown_output(self, runner: CliRunner) -> None:
        result = runner.invoke(env_vars, ['--format', 'markdown'])

        assert result.exit_code == 0
        assert '| Variable | Type | Default | Description |' in result.output
        assert '| `EVENTS_CONCURRENCY_LIMIT` | int | `10` |' in result.output
