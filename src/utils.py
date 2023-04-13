from os import environ
from pathlib import Path


def get_build_version() -> str | None:
    path = Path(__file__).parents[1].joinpath('GIT_SHA')
    if not path.exists():
        return None

    with path.open() as fh:
        return fh.read().strip()


def set_env(name: str, value: str) -> None:
    if value is not None:
        environ[name] = value
