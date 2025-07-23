from pathlib import Path

import yaml

from src.validators.keystores.local import KeystoreFile, LocalKeystore


def generate_validator_definitions_file(
    keystores_dir: Path,
    keystore_files: list[KeystoreFile],
    output_path: Path,
) -> None:
    """
    Generates a validator definitions file for Lighthouse.
    """
    keystore_files = LocalKeystore.list_keystore_files()
    items: list[dict] = []

    # Read keystore files and create items for the YAML file
    for keystore_file in keystore_files:
        key_index, public_key = LocalKeystore.read_keystore_file(keystore_file)
        items.append(
            {
                'key_index': key_index,  # temporary, not used by Lighthouse
                'enabled': True,
                'voting_public_key': public_key,
                'type': 'local_keystore',
                'voting_keystore_path': str(keystores_dir / keystore_file.name),
                'voting_keystore_password_path': str(keystore_file.password_file),
            }
        )

    # Sort items by `key_index` for consistency
    items.sort(key=lambda x: x['key_index'])
    for item in items:
        del item['key_index']

    # Write the YAML file
    with open(output_path, 'w', encoding='utf-8') as f:
        yaml.dump(items, f, explicit_start=True)
