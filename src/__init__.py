from pathlib import Path

import tomllib


def _get_project_meta() -> dict:
    toml_path = Path(__file__).parents[1].joinpath('pyproject.toml')

    with toml_path.open(mode='rb') as pyproject:
        return tomllib.load(pyproject)['tool']['poetry']


__version__ = _get_project_meta()['version']
