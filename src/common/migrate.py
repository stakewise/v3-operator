import json
import shutil
from os import makedirs, path
from pathlib import Path

from eth_typing import HexStr

from src.config.config import OperatorConfig
from src.config.settings import PUBLIC_KEYS_FILENAME
from src.validators.keystores.local import LocalKeystore


def migrate_to_multivault(vault_dir: Path, data_dir: Path) -> None:
    """Copy operator files from single vault directory to multivault directory."""
    vault_config = vault_dir / 'config.json'
    with vault_config.open('r') as f:
        config = json.load(f)
    network = config.get('network')
    new_dir = Path(data_dir) / network
    new_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(vault_config, new_dir / 'config.json')
    shutil.copytree(vault_dir / 'wallet', new_dir / 'wallet')
    shutil.copytree(vault_dir / 'keystores', new_dir / 'keystores')
    shutil.copy(vault_dir / 'operator.db', new_dir / 'operator.db')

    # export public keys
    operator_config = OperatorConfig(Path(new_dir))
    operator_config.load(network=network)
    public_keys = LocalKeystore.get_public_keys_from_keystore_files()
    filename = new_dir.data_dir / PUBLIC_KEYS_FILENAME

    _export_public_keys(public_keys=public_keys, filename=filename)


def _export_public_keys(filename: Path, public_keys: list[HexStr]) -> None:
    makedirs(path.dirname(path.abspath(filename)), exist_ok=True)
    with open(filename, 'w', encoding='utf-8') as f:
        for public_key in public_keys:
            f.write(f'{public_key}\n')
