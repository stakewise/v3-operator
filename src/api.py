from starlette.applications import Starlette
from starlette.routing import Route

from src.validators.endpoints import approve_validators, get_validators

app = Starlette(
    routes=[
        Route('/validators', get_validators, methods=['GET']),
        Route('/validators', approve_validators, methods=['POST']),
    ]
)
