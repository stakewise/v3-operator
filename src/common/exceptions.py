INVALID_ORACLES_REQUEST = 'Invalid oracles request'
NOT_ENOUGH_ORACLE_APPROVALS = 'Not enough oracle approvals received'


class InvalidOraclesRequestError(ValueError):
    def __init__(self):
        super().__init__(INVALID_ORACLES_REQUEST)


class NotEnoughOracleApprovalsError(ValueError):
    def __init__(self, num_votes: int, threshold: int):
        super().__init__(NOT_ENOUGH_ORACLE_APPROVALS)
        self.num_votes = num_votes
        self.threshold = threshold
