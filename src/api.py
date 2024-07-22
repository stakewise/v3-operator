from starlette.applications import Starlette
from starlette.routing import Route

from src.validators.api.endpoints import get_validators, submit_validators

app = Starlette(
    routes=[
        Route('/validators', get_validators, methods=['GET']),
        Route('/validators', submit_validators, methods=['POST']),
    ]
)
