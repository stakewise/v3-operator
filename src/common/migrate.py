import json
import shutil
from pathlib import Path


def migrate_to_multivault(vault_dir: Path, root_dir: Path) -> None:
    """Copy operator files from single vault directory to multivault directory."""
    vault_config = vault_dir / 'config.json'
    with vault_config.open('r') as f:
        config = json.load(f)
    network = config['network']
    new_dir = root_dir / network
    new_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(vault_config, new_dir / 'config.json')
    shutil.copytree(vault_dir / 'wallet', new_dir / 'wallet')
    shutil.copytree(vault_dir / 'keystores', new_dir / 'keystores')
    shutil.copy(vault_dir / 'operator.db', new_dir / 'operator.db')
