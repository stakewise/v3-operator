import random
import string
from secrets import randbits

from faker import Faker
from faker.providers import BaseProvider
from py_ecc.bls import G2ProofOfPossession
from web3 import Web3
from web3.types import Wei

w3 = Web3()
faker = Faker()


class W3Provider(BaseProvider):
    def public_key(self) -> str:
        seed = randbits(256).to_bytes(32, 'big')
        private_key = G2ProofOfPossession.KeyGen(seed)
        return str(private_key)

    def eth_address(self) -> str:
        account = w3.eth.account.create()
        return account.address

    def eth_proof(self) -> str:
        return '0x' + ''.join(random.choices('abcdef' + string.digits, k=64))

    def eth_signature(self) -> str:
        return '0x' + ''.join(random.choices('abcdef' + string.digits, k=194))

    def eth_public_key(self) -> str:
        return '0x' + ''.join(random.choices('abcdef' + string.digits, k=98))

    def wei_amount(self) -> Wei:
        eth_value = faker.random_int(10, 1000)
        return w3.to_wei(eth_value, 'ether')


faker.add_provider(W3Provider)
