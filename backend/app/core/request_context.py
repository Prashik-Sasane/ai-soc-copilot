from contextvars import ContextVar
from typing import Optional

request_id_ctx: ContextVar[Optional[str]] = ContextVar("request_id", default=None)


def get_request_id() -> Optional[str]:
    return request_id_ctx.get()


def set_request_id(value: str) -> None:
    request_id_ctx.set(value)
