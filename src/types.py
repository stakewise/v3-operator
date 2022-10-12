from typing import List, TypedDict

from eth_typing import ChecksumAddress, HexStr


class ValidatorDepositData(TypedDict):
    operator: ChecksumAddress
    public_key: HexStr
    withdrawal_credentials: HexStr
    deposit_data_root: HexStr
    deposit_data_signature: HexStr
    proof: List[HexStr]
