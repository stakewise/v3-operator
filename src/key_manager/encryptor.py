from typing import cast

# pycryptodome lib used
from Crypto.Cipher import AES  # nosec
from Crypto.Cipher._mode_eax import EaxMode  # nosec
from Crypto.Random import get_random_bytes  # nosec

from src.common.contrib import bytes_to_str, str_to_bytes

CIPHER_KEY_LENGTH = 32


class Encryptor:
    def __init__(self, key: str | None = None):
        if key:
            self.str_key = key
            self.bytes_key = str_to_bytes(key)
        else:
            self.bytes_key = self._generate_cipher_key()
            self.str_key = bytes_to_str(self.bytes_key)

    def encrypt(self, data: str):
        cipher = self._get_cipher()
        encrypted_data = cipher.encrypt(bytes(data, 'ascii'))
        return encrypted_data, cipher.nonce

    def decrypt(self, data: str, nonce: str) -> str:
        cipher = self._restore_cipher(nonce=nonce)
        private_key = cipher.decrypt(str_to_bytes(data))
        return private_key.decode('ascii')

    def _restore_cipher(self, nonce: str) -> EaxMode:
        cipher = AES.new(self.bytes_key, AES.MODE_EAX, nonce=str_to_bytes(nonce))
        return cast(EaxMode, cipher)

    def _generate_cipher_key(self) -> bytes:
        return get_random_bytes(CIPHER_KEY_LENGTH)

    def _get_cipher(self) -> EaxMode:
        cipher = AES.new(self.bytes_key, AES.MODE_EAX)
        return cast(EaxMode, cipher)
