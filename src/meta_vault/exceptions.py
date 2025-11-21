from src.common.typings import ExitRequest


class ClaimDelayNotPassedException(Exception):
    def __init__(self, exit_request: ExitRequest):
        self.exit_request = exit_request
        super().__init__(
            f'Claim delay for exit request from vault {exit_request.vault} '
            f'with position ticket {exit_request.position_ticket} has not passed yet.'
        )
