import tomllib
from pathlib import Path


def _get_project_meta() -> dict:
    toml_path = Path(__file__).parents[1].joinpath('pyproject.toml')

    with toml_path.open(mode='rb') as pyproject:
        return tomllib.load(pyproject)['project']


# Release tags are prefixed with `v` (e.g. `v5.1.2`), pyproject.toml holds the PEP 440 version
__version__ = f'v{_get_project_meta()['version']}'
