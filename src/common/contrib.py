import collections
from base64 import b64decode, b64encode

import click


def chunkify(items, size):
    for i in range(0, len(items), size):
        yield items[i : i + size]


def greenify(value):
    return click.style(value, bold=True, fg='green')


def bytes_to_str(value: bytes) -> str:
    return b64encode(value).decode('ascii')


def str_to_bytes(value: str) -> bytes:
    return b64decode(value)


def is_lists_equal(x: list, y: list) -> bool:
    return collections.Counter(x) == collections.Counter(y)
