INVALID_ORACLES_REQUEST = 'Invalid oracles request'
NOT_ENOUGH_ORACLE_APPROVALS = 'Not enough oracle approvals received'


class InvalidOraclesRequestError(ValueError):
    def __init__(self, *args, **kwargs):  # type: ignore
        super().__init__(INVALID_ORACLES_REQUEST, *args, **kwargs)


class NotEnoughOracleApprovalsError(ValueError):
    def __init__(  # type: ignore
        self, num_votes: int, threshold: int, failed_endpoints: list[str], *args, **kwargs
    ):
        super().__init__(NOT_ENOUGH_ORACLE_APPROVALS, *args, **kwargs)
        self.num_votes = num_votes
        self.threshold = threshold
        self.failed_endpoints = failed_endpoints
