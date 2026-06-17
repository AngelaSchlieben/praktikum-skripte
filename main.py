import argparse
import csv
import os
import time
from collections import defaultdict
from http import HTTPStatus

import requests

from Types.token_report import RawToken, Report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Liest Token-Daten aus eduMFA per API und schreibt einen CSV-Report."
    )
    parser.add_argument("--url", help="Basis-URL der eduMFA-Instanz")
    parser.add_argument("--user", help="Admin-Benutzername")
    parser.add_argument("--password", help="Admin-Passwort")
    return parser.parse_args()


def authenticate(url: str, user: str, password: str) -> str | None:
    try:
        url = f"{url}/auth"
        payload = {"username": user, "password": password}
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code != 200:
            status = HTTPStatus(response.status_code)
            print(f"Code: {status.value}")
            print(f"Name: {status.name}")
            print(f"Info: {status.description}")
            exit()
        return response.json()["result"]["value"]["token"]
    except (
        requests.exceptions.ConnectionError,    # URL nicht erreichbar
        requests.exceptions.MissingSchema,      # URL-Format unvollständig
        requests.exceptions.InvalidSchema,      # URL-Protokoll nicht unterstützt
        requests.exceptions.InvalidURL          # URL ungültig
    ) as err:
        print(type(err).__name__)
        print("Verbindung zur angegebenen URL konnte nicht hergestellt werden. Bitte URL prüfen.")
        exit()
    except (requests.exceptions.ReadTimeout) as err:    # Zeitablauf
        print(type(err).__name__)
        exit()


def fetch_tokens(url: str, auth_token: str) -> list[RawToken]:
    url = f"{url}/token"
    header = {"Authorization": auth_token}
    response = requests.get(url, headers=header)
    return response.json()["result"]["value"]["tokens"]


def build_report(tokens: list[RawToken]) -> list[Report]:
    by_user = defaultdict(list) # erzeugt dict mit leeren Listen als value für neue keys
    for t in tokens:
        if t.get("username") == "" or t.get("username") == "**resolver error**" or t.get("username") == None:
            by_user[("UNKNOWN", "UNKNOWN")].append(t) # verwaiste Token zusammenfassen
        else:
            by_user[(t.get("username"), t.get("user_realm"))].append(t)
    reports: list[Report] = []
    for (username, realm), user_tokens in sorted(by_user.items()):
        reports.append(
            {
                "username": username,
                "user_realm": realm,
                "anzahl_token": len(user_tokens),
                "anzahl_nutzungen_gesamt": sum(
                    int(x["info"].get("count_auth_success", 0)) for x in user_tokens
                ),
                "tokens": [
                    {
                        "serial": x.get("serial"),
                        "tokentype": x.get("tokentype"),
                        "count_auth_success": int(
                            x["info"].get("count_auth_success", 0)
                        ),
                    }
                    for x in user_tokens
                ],
            }
        )
    return reports


def write_csv(reports: list[Report]):
    path = "csv_reports"
    os.makedirs(path, exist_ok=True)
    filename = "token_report_" + time.strftime("%Y%m%d_%H%M%S") + ".csv"
    new_file = os.path.join(path, filename)
    with open(new_file, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "username",
                "user_realm",
                "anzahl_token",
                "anzahl_nutzungen_gesamt",
                "serial",
                "tokentype",
                "count_auth_success",
            ]
        )
        for entry in reports:
            for t in entry["tokens"]:
                writer.writerow(
                    [
                        entry["username"],
                        entry["user_realm"],
                        entry["anzahl_token"],
                        entry["anzahl_nutzungen_gesamt"],
                        t["serial"],
                        t["tokentype"],
                        t["count_auth_success"],
                    ]
                )


def main():
    args = parse_args()
    url = args.url
    user = args.user
    password = args.password
    auth_token = authenticate(url, user, password)
    tokens = fetch_tokens(url, auth_token) # type: ignore
    report = build_report(tokens)
    print(report)
    write_csv(report)


if __name__ == "__main__":
    main()
