from unittest.mock import mock_open, patch

import pytest
from click import BadParameter
from sw_utils.tests import faker

from src.common.validators import (
    _is_public_key,
    validate_db_uri,
    validate_eth_address,
    validate_eth_addresses,
    validate_min_deposit_amount_gwei,
    validate_public_keys,
    validate_public_keys_file,
)
from src.config.settings import DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI


def test_validate_eth_address():
    # returns_checksum_address_for_valid_eth_address
    address = faker.eth_address()
    result = validate_eth_address(None, None, address)
    assert result == address
    result = validate_eth_address(None, None, address.lower())
    assert result == address

    # returns_none_for_empty_value
    result = validate_eth_address(None, None, None)
    assert result is None

    # raises_error_for_invalid_eth_address
    with pytest.raises(BadParameter, match='Invalid Ethereum address'):
        validate_eth_address(None, None, 'invalid_address')
    # raises_error_for_invalid_eth_address
    with pytest.raises(BadParameter, match='Invalid Ethereum address'):
        validate_eth_address(None, None, '0x742d35Cc')


def test_validate_eth_addresses():
    # returns_none_for_empty_eth_addresses
    result = validate_eth_addresses(None, None, None)
    assert result is None

    # returns_valid_eth_addresses_as_string
    address_1 = faker.eth_address()
    address_2 = faker.eth_address()

    result = validate_eth_addresses(None, None, ','.join([address_1, address_2.lower()]))
    assert result == ','.join([address_1, address_2.lower()])

    # raises_error_for_invalid_eth_address_in_list
    with pytest.raises(BadParameter, match='Invalid Ethereum address'):
        validate_eth_addresses(None, None, ','.join([address_1, 'invalid_address']))

    # raises_error_for_all_invalid_eth_addresses
    with pytest.raises(BadParameter, match='Invalid Ethereum address'):
        validate_eth_addresses(None, None, 'invalid_address1,invalid_address2')


def test_validate_min_deposit_amount_gwei():
    # returns_value_when_above
    result = validate_min_deposit_amount_gwei(None, None, DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI + 1000)
    assert result == DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI + 1000

    # returns_value_when_equal_to_minimum
    result = validate_min_deposit_amount_gwei(None, None, DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI)
    assert result == DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI

    # raises_error_when_below_minimum
    with pytest.raises(
        BadParameter,
        match=f"min-deposit-amount-gwei must be greater than or equal to {DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI} Gwei",
    ):
        validate_min_deposit_amount_gwei(None, None, DEFAULT_MIN_DEPOSIT_AMOUNT_GWEI - 1)


def test_validate_public_keys():
    public_key_1 = faker.validator_public_key()
    public_key_2 = faker.validator_public_key()
    # returns_list_of_valid_public_keys
    result = validate_public_keys(None, None, public_key_1 + ',' + public_key_2)
    assert result == [public_key_1, public_key_2]

    # returns_none_for_empty_value
    result = validate_public_keys(None, None, None)
    assert result is None

    # raises_error_for_invalid_public_key
    with pytest.raises(BadParameter, match='Invalid validator public key'):
        validate_public_keys(None, None, 'invalid_key')

    # raises_error_for_mixed_valid_and_invalid_public_keys
    with pytest.raises(BadParameter, match='Invalid validator public key'):
        validate_public_keys(None, None, public_key_1 + ',invalid_key')
    with pytest.raises(BadParameter, match='Invalid validator public key'):
        validate_public_keys(None, None, public_key_1[:-2])


def test_validate_public_keys_file():
    public_key_1 = faker.validator_public_key()
    public_key_2 = faker.validator_public_key()

    # returns_none_for_empty_file_path
    result = validate_public_keys_file(None, None, None)
    assert result is None

    # returns_file_path_when_all_keys_are_valid
    mock_file_content = public_key_1 + '\n'
    with patch('builtins.open', mock_open(read_data=mock_file_content)):
        result = validate_public_keys_file(None, None, 'mock_file_path')
    assert result == 'mock_file_path'

    mock_file_content = public_key_1 + '\n' + public_key_2 + '\n'
    with patch('builtins.open', mock_open(read_data=mock_file_content)):
        result = validate_public_keys_file(None, None, 'mock_file_path')
    assert result == 'mock_file_path'

    # raises_error_for_invalid_key_in_file
    mock_file_content = 'invalid_key\n'
    with patch('builtins.open', mock_open(read_data=mock_file_content)):
        with pytest.raises(BadParameter, match='Invalid validator public key: invalid_key'):
            validate_public_keys_file(None, None, 'mock_file_path')

    # raises_error_for_mixed_valid_and_invalid_keys_in_file
    mock_file_content = public_key_1[:-2] + '\n' 'invalid_key\n'
    with patch('builtins.open', mock_open(read_data=mock_file_content)):
        with pytest.raises(
            BadParameter, match=f"Invalid validator public key: {public_key_1[:-2]}"
        ):
            validate_public_keys_file(None, None, 'mock_file_path')


def test_is_public_key():
    # returns_true_for_valid_public_key
    result = _is_public_key('0x' + 'a' * 96)
    assert result is True

    # returns_false_for_invalid_length_public_key
    result = _is_public_key('0x' + 'a' * 95)
    assert result is False

    # returns_false_for_non_hex_string
    result = _is_public_key('0x' + 'g' * 96)
    assert result is False

    # returns_false_for_empty_string
    result = _is_public_key('')
    assert result is False


def test_validate_db_uri():
    # returns_value_for_valid_db_uri
    result = validate_db_uri(None, None, 'postgresql://user:password@localhost/dbname')
    assert result == 'postgresql://user:password@localhost/dbname'

    # raises_error_for_missing_protocol
    with pytest.raises(BadParameter, match='Invalid database connection string'):
        validate_db_uri(None, None, 'user:password@localhost/dbname')

    # raises_error_for_missing_credentials
    with pytest.raises(BadParameter, match='Invalid database connection string'):
        validate_db_uri(None, None, 'postgresql://@localhost/dbname')

    # raises_error_for_missing_host
    with pytest.raises(BadParameter, match='Invalid database connection string'):
        validate_db_uri(None, None, 'postgresql://user:password@/dbname')

    # raises_error_for_missing_database_name
    with pytest.raises(BadParameter, match='Invalid database connection string'):
        validate_db_uri(None, None, 'postgresql://user:password@localhost/')
