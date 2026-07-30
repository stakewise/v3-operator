"""
Self-documenting wrapper around `decouple.config`.

Every environment variable the operator reads is declared through
`decouple_config` below, which records its name, default, cast and description
in `REGISTRY` in addition to resolving the value. The `env-vars` CLI command
renders the registry, so the documentation cannot drift from the code.
"""

import typing
from dataclasses import dataclass

from decouple import Csv
from decouple import config as _decouple_config
from decouple import undefined


@dataclass(frozen=True)
class EnvVar:
    name: str
    group: str
    description: str
    default: typing.Any
    cast: typing.Any
    default_repr: str | None = None

    @property
    def type_name(self) -> str:
        if isinstance(self.cast, Csv):
            return 'list'
        if isinstance(self.cast, type):
            return self.cast.__name__
        return 'str'

    @property
    def formatted_default(self) -> str:
        if self.default_repr is not None:
            return self.default_repr
        if isinstance(self.default, undefined.__class__):
            return '<required>'
        if isinstance(self.default, bool):
            return 'true' if self.default else 'false'
        if self.default is None:
            return 'none'
        if self.default == '':
            return "'' (empty)"
        return str(self.default)


# Keyed by variable name so that repeated `Settings.set()` calls do not
# duplicate entries. Insertion order is the declaration order.
REGISTRY: dict[str, EnvVar] = {}


# pylint: disable-next=too-many-arguments
def decouple_config(
    option: str,
    default: typing.Any = undefined,
    cast: typing.Any = undefined,
    group: str = 'Other',
    description: str = '',
    default_repr: str | None = None,
) -> typing.Any:
    """
    Drop-in replacement for `decouple.config` that also registers the variable.

    `group` and `description` are metadata only — they are used to render the
    `env-vars` command output and are ignored when resolving the value.
    `default_repr` overrides how the default is displayed, for defaults that are
    computed at runtime (e.g. derived from the network or the vault directory).
    """
    REGISTRY[option] = EnvVar(
        name=option,
        group=group,
        description=description,
        default=default,
        cast=cast,
        default_repr=default_repr,
    )
    return _decouple_config(option, default=default, cast=cast)


def get_env_vars() -> list[EnvVar]:
    """Return all registered variables, sorted by group and then by name."""
    return sorted(REGISTRY.values(), key=lambda var: (var.group, var.name))
