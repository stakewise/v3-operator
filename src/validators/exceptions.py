class RegistryRootChangedError(ValueError):
    def __init__(self) -> None:
        super().__init__('Validators registry root has changed')


class ValidatorIndexUnknownError(Exception):
    """Validator approvals are blocked until the builders onboarding at the fork is resolved."""


class KeystoreException(Exception): ...


class EmptyRelayerResponseException(Exception): ...


class FundingException(Exception): ...


class ConsolidationError(Exception): ...
