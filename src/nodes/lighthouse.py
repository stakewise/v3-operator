from pathlib import Path
from venv import logger

import yaml

from src.validators.keystores.local import KeystoreFile, LocalKeystore


def update_validator_definitions_file(
    keystores_dir: Path,
    keystore_files: list[KeystoreFile],
    output_path: Path,
) -> bool:
    """
    Updates the Lighthouse validator definitions YAML file
    if there are changes in the keystore files.

    Args:
        keystores_dir (Path): Directory containing keystore files.
        keystore_files (list[KeystoreFile]): List of keystore file objects.
        output_path (Path): Path to the validator definitions YAML file.

    Returns:
        bool: True if the file was updated, False if no changes were detected.
    """
    keystore_files = LocalKeystore.list_keystore_files()
    current_items: list[dict] = []

    # Load existing YAML file if it exists
    if output_path.exists():
        with open(output_path, 'r', encoding='utf-8') as f:
            previous_items = yaml.safe_load(f) or []
    else:
        previous_items = []
    previous_public_keys = {item['voting_public_key'] for item in previous_items}

    # Read keystore files and create items for the YAML file
    for keystore_file in keystore_files:
        key_index, public_key = LocalKeystore.read_keystore_file(keystore_file)
        current_items.append(
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
    current_items.sort(key=lambda x: x['key_index'])
    for item in current_items:
        del item['key_index']

    # Check if the current items differ from the previous ones
    current_public_keys = {item['voting_public_key'] for item in current_items}
    if current_public_keys == previous_public_keys:
        logger.info('No changes in validator definitions file, skipping update.')
        return False

    # Write the YAML file
    with open(output_path, 'w', encoding='utf-8') as f:
        yaml.dump(current_items, f, explicit_start=True)

    return True
