from eth_typing import HexStr

INVALID_ORACLES_REQUEST = 'Invalid oracles request'
NOT_ENOUGH_ORACLE_APPROVALS = 'Not enough oracle approvals received'


class InvalidOraclesRequestError(ValueError):
    def __init__(self) -> None:
        super().__init__(INVALID_ORACLES_REQUEST)


class NotEnoughOracleApprovalsError(ValueError):
    def __init__(self, num_votes: int, threshold: int):
        super().__init__(NOT_ENOUGH_ORACLE_APPROVALS)
        self.num_votes = num_votes
        self.threshold = threshold


class MissingConsolidationDataError(RuntimeError):
    """
    Raised when code that relies on consolidation data gets validators built without
    `with_consolidations=True`: treating the missing data as "not consolidating" would
    silently include consolidation sources and targets.
    """

    MESSAGE = (
        'Consolidation data is not loaded for validator {}. '
        'Build the validators with `with_consolidations=True`.'
    )

    def __init__(self, public_key: HexStr):
        super().__init__()
        self.public_key = public_key

    def __str__(self) -> str:
        return self.MESSAGE.format(self.public_key)
