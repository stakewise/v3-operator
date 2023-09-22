INVALID_ORACLES_REQUEST = 'Invalid oracles request'
VALIDATOR_INDEX_CHANGED = 'Not enough oracle approvals received'


class InvalidOraclesRequestError(ValueError):
    def __init__(self, *args, **kwargs):
        super().__init__(INVALID_ORACLES_REQUEST, *args, **kwargs)


class NotEnoughOracleApprovalsError(ValueError):
    def __init__(self, *args, **kwargs):
        super().__init__(VALIDATOR_INDEX_CHANGED, *args, **kwargs)
