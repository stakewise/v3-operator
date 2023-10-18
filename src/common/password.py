import secrets
import string
from pathlib import Path

SPECIAL_CHARS = '!@#$%^&*()_'


def generate_password() -> str:
    alphabet = string.ascii_letters + string.digits + SPECIAL_CHARS
    lower_set = set(string.ascii_lowercase)
    upper_set = set(string.ascii_uppercase)
    digits_set = set(string.digits)
    special_set = set(SPECIAL_CHARS)
    while True:
        password = [secrets.choice(alphabet) for _ in range(20)]
        password_set = set(password)
        if (
            upper_set.intersection(password_set)
            and lower_set.intersection(password_set)
            and special_set.intersection(password_set)
            and digits_set.intersection(password_set)
        ):
            return ''.join(password)


def get_or_create_password_file(password_file: Path) -> str:
    try:
        with open(password_file, 'r', encoding='utf-8') as file:
            password = file.readline()
    except FileNotFoundError:
        password = generate_password()
        password_file.parent.mkdir(parents=True, exist_ok=True)
        with open(password_file, 'w', encoding='utf-8') as file:
            file.write(password)

    return password
