from pathlib import Path


def get_build_version():
    path = Path(__file__).parents[1].joinpath('GITSHA')
    if not path.exists():
        return 'unknown'

    with path.open() as fh:
        return fh.read().strip()
