from typing import TypedDict


class Token(TypedDict):
    username: str | None
    realm: str | None
    serial: str | None
    token_type: str | None
    count_auth_success: int | None


class Report(TypedDict):
    username: str
    realm: str
    anzahl_token: int
    tokens: Token
