from pathlib import Path

import click

from src.common.validators import validate_db_uri
from src.key_manager.database import Database, check_db_connection


@click.option(
    '--db-url',
    help='The database connection address.',
    prompt="Enter the database connection string, ex. 'postgresql://username:pass@hostname/dbname'",
    callback=validate_db_uri,
)
@click.option(
    '--output-dir',
    required=False,
    help='The directory to save configuration files. Defaults to ./data/configs.',
    default='./data',
    type=click.Path(exists=False, file_okay=False, dir_okay=True),
)
@click.command(help='Get operator configuration files for remote database.')
# pylint: disable-next=too-many-arguments,too-many-locals
def sync_operator(
    db_url: str,
    output_dir: str,
) -> None:
    check_db_connection(db_url)
    database = Database(db_url=db_url)

    configs = database.fetch_configs()

    if not configs:
        raise click.ClickException('Database does not contain any configuration files')

    Path(output_dir).mkdir(exist_ok=True, parents=True)

    for config in configs:
        config_path = Path(output_dir) / config.name
        with config_path.open('w', encoding='utf-8') as f:
            f.write(config.data)

    click.secho(
        f'Done. Saved {len(configs)} configuration files.',
        bold=True,
        fg='green',
    )
