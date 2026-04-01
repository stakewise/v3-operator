class NodeException(Exception):
    """Base exception class for node-related errors."""


class NodeFailedToStartError(NodeException):
    """Exception raised when a node fails to start."""

    def __init__(self, process_name: str):
        super().__init__(f'{process_name} failed to start')
        self.process_name = process_name
