import os
import time

import requests
import argparse
from collections import defaultdict
import csv

from Types.token_report import Report, Token


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Liest Token-Daten aus eduMFA per API und schreibt einen CSV-Report."
    )
    parser.add_argument("--url", help="Basis-URL der eduMFA-Instanz")
    parser.add_argument("--user", help="Admin-Benutzername")
    parser.add_argument("--password", help="Admin-Passwort")
    return parser.parse_args()


def authenticate(url: str, user: str, password: str) -> str:
    # Authentifizierung des Users, der die Abfrage macht
    url = f"{url}/auth"
    payload = {"username": user, "password": password}
    response = requests.post(url, json=payload)
    if response.status_code == 401:
        print(f"Error: {response.status_code} Unauthorized")
        exit()
    if response.status_code != 200:
        print(f"Error: {response.status_code}")
        exit()
    return response.json()["result"]["value"]["token"]


def fetch_tokens(url: str, auth_token: str) -> list[Token]:
    url = f"{url}/token"
    header = {"Authorization": auth_token}
    response = requests.get(url, headers=header)
    return response.json()["result"]["value"]["tokens"]


def build_report(tokens: list[Token]) -> list[Report]:
    by_user = defaultdict(
        list
    )  # erzeugt automatisch eine leere Liste, wenn auf einen noch nicht existierenden Schlüssel zugegriffen wird
    for t in tokens:
        by_user[(t.get("username"), t.get("user_realm"))].append(t)
    reports = []
    for (username, realm), user_tokens in sorted(by_user.items()):
        reports.append(
            {
                "username": username,
                "realm": realm,
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


def write_csv(reports: Report):
    path = "csv_reports"
    os.makedirs(path, exist_ok=True)
    filename = "token_report_" + time.strftime("%Y%m%d_%H%M%S") + ".csv"
    new_file = os.path.join(path, filename)
    fieldnames = [
        "username",
        "realm",
        "anzahl_token",
        "anzahl_nutzungen_gesamt",
        "serial",
        "tokentype",
        "count_auth_success",
    ]
    with open(new_file, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for entry in reports:
            for t in entry["tokens"]:
                writer.writerow(
                    {
                        "username": entry["username"],
                        "realm": entry["realm"],
                        "anzahl_token": entry["anzahl_token"],
                        "anzahl_nutzungen_gesamt": entry["anzahl_nutzungen_gesamt"],
                        "serial": t["serial"],
                        "tokentype": t["tokentype"],
                        "count_auth_success": t["count_auth_success"],
                    }
                )


def main():
    args = parse_args()
    url = args.url
    user = args.user
    password = args.password
    auth_token = authenticate(url, user, password)
    tokens = fetch_tokens(url, auth_token)
    report = build_report(tokens)
    print(report)
    write_csv(report)


if __name__ == "__main__":
    main()
