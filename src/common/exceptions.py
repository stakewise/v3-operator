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


class ExecutionBehindConsensusError(RuntimeError):
    def __init__(self, execution_block_number: int, consensus_block_number: int):
        super().__init__(
            f'The execution client has not imported the consensus head block yet: '
            f'execution block {execution_block_number}, '
            f'consensus block {consensus_block_number}'
        )
        self.execution_block_number = execution_block_number
        self.consensus_block_number = consensus_block_number
