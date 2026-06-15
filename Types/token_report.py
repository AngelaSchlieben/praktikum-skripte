from typing import TypedDict


class Token(TypedDict):
    username: str | None
    realm: str | None
    serial: str | None
    tokentype: str | None
    count_auth_success: int | None


class Report(TypedDict):
    username: str
    user_realm: str
    anzahl_token: int
    anzahl_nutzungen_gesamt : int
    tokens: list[Token]
