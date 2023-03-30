import os

from web3 import Web3
from web3.types import Wei

WAD = Web3.to_wei(1, 'ether')
MGNO_RATE = Web3.to_wei(32, 'ether')


def convert_to_gno(mgno_amount: Wei) -> Wei:
    """Converts mGNO to GNO."""
    return Wei(mgno_amount * WAD // MGNO_RATE)


def count_files_in_folder(path):
    count = 0
    for _, _, files in os.walk(path):
        count += len(files)
    return count
