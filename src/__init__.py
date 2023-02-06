from pathlib import Path

import tomli


def _get_project_meta():
    toml_path = Path(__file__).parents[1].joinpath('pyproject.toml')

    with toml_path.open(mode='rb') as pyproject:
        return tomli.load(pyproject)['tool']['poetry']


__version__ = _get_project_meta()['version']
