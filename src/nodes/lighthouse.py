from pathlib import Path

import yaml

from src.validators.keystores.local import KeystoreFile, LocalKeystore


def update_validator_definitions_file(
    keystore_files: list[KeystoreFile],
    output_path: Path,
) -> None:
    """
    Updates the Lighthouse validator definitions YAML file
    if there are changes in the keystore files.

    Args:
        keystore_files (list[KeystoreFile]): List of keystore file objects.
        output_path (Path): Path to the validator definitions YAML file.
    """
    current_items: list[dict] = []

    # Read keystore files and create items for the YAML file
    for keystore_file in keystore_files:
        key_index, public_key = LocalKeystore.parse_keystore_file(keystore_file)
        current_items.append(
            {
                'key_index': key_index,  # temporary, not used by Lighthouse
                'enabled': True,
                'voting_public_key': public_key,
                'type': 'local_keystore',
                'voting_keystore_path': str(keystore_file.file),
                'voting_keystore_password_path': str(keystore_file.password_file),
            }
        )

    # Sort items by `key_index` for consistency
    current_items.sort(key=lambda x: x['key_index'])
    for item in current_items:
        del item['key_index']

    # Write the YAML file
    with open(output_path, 'w', encoding='utf-8') as f:
        yaml.dump(current_items, f, explicit_start=True)
