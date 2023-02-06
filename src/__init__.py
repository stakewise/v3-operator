import tomli


def _get_project_meta():
    with open('pyproject.toml', mode='rb') as pyproject:
        return tomli.load(pyproject)['tool']['poetry']


__version__ = _get_project_meta()['version']
