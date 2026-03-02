class RegistryRootChangedError(ValueError):
    def __init__(self) -> None:
        super().__init__('Validators registry root has changed')


class KeystoreException(Exception): ...


class EmptyRelayerResponseException(Exception): ...


class FundingException(Exception): ...


class ConsolidationError(Exception): ...
