INVALID_ORACLES_REQUEST = 'Invalid oracles request'
NOT_ENOUGH_ORACLE_APPROVALS = 'Not enough oracle approvals received'


class InvalidOraclesRequestError(ValueError):
    def __init__(self, *args, **kwargs):
        super().__init__(INVALID_ORACLES_REQUEST, *args, **kwargs)


class NotEnoughOracleApprovalsError(ValueError):
    def __init__(self, *args, **kwargs):
        super().__init__(NOT_ENOUGH_ORACLE_APPROVALS, *args, **kwargs)
