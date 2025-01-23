REGISTRY_ROOT_CHANGED = 'Validators registry root has changed'
VALIDATOR_INDEX_CHANGED = 'Validator index has changed'


class KeystoreException(Exception): ...


class RegistryRootChangedError(ValueError):
    def __init__(self) -> None:
        super().__init__(REGISTRY_ROOT_CHANGED)


class ValidatorIndexChangedError(ValueError):
    def __init__(self) -> None:
        super().__init__(VALIDATOR_INDEX_CHANGED)


class MissingDepositDataValidatorsException(Exception): ...
