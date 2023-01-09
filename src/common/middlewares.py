from typing import Any, Callable, Collection, Union, cast

# pylint: disable=no-name-in-module
from cytoolz.dicttoolz import assoc
from eth_account.signers.local import LocalAccount
from eth_keys.datatypes import PrivateKey
from eth_typing import ChecksumAddress, HexStr
from eth_utils.toolz import curry
from web3 import Web3
from web3._utils.async_transactions import fill_transaction_defaults
from web3.middleware.signing import format_transaction, gen_normalized_accounts
from web3.types import AsyncMiddleware, Middleware, RPCEndpoint, RPCResponse, TxParams

_PrivateKey = Union[LocalAccount, PrivateKey, HexStr, bytes]


@curry
async def fill_nonce(w3: 'Web3', transaction: TxParams) -> TxParams:
    if 'from' in transaction and 'nonce' not in transaction:
        return assoc(
            transaction,
            'nonce',
            await w3.eth.get_transaction_count(  # type: ignore
                cast(ChecksumAddress, transaction['from'])
            ),
        )
    return transaction


# TODO: can be removed once https://github.com/ethereum/web3.py/issues/2773 is fixed
def construct_async_sign_and_send_raw_middleware(
    private_key_or_account: Union[_PrivateKey, Collection[_PrivateKey]]
) -> Middleware:
    """Capture transactions sign and send as raw transactions


    Keyword arguments:
    private_key_or_account -- A single private key or a tuple,
    list or set of private keys. Keys can be any of the following formats:
      - An eth_account.LocalAccount object
      - An eth_keys.PrivateKey object
      - A raw private key as a hex string or byte string
    """

    accounts = gen_normalized_accounts(private_key_or_account)

    async def sign_and_send_raw_middleware(
        make_request: Callable[[RPCEndpoint, Any], Any], _async_w3: 'Web3'
    ) -> AsyncMiddleware:

        async def middleware(method: RPCEndpoint, params: Any) -> RPCResponse:
            if method != 'eth_sendTransaction':
                return await make_request(method, params)

            transaction = await fill_nonce(_async_w3, params[0])
            transaction = await fill_transaction_defaults(_async_w3, transaction)
            transaction = format_transaction(transaction)

            if 'from' not in transaction:
                return await make_request(method, params)

            if transaction.get('from') not in accounts:
                return await make_request(method, params)

            # pylint: disable=unsubscriptable-object
            account = accounts[transaction['from']]
            raw_tx = account.sign_transaction(transaction).rawTransaction

            return await make_request(RPCEndpoint('eth_sendRawTransaction'), [Web3.to_hex(raw_tx)])

        return middleware

    return sign_and_send_raw_middleware
