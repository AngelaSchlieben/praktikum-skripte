# /// script
# requires-python = ">=3.11"
# dependencies = ["requests"]
# ///

import os
import time

import requests
import argparse
from collections import defaultdict
import csv

def parse_args():
    parser = argparse.ArgumentParser(
        description="Liest Token-Daten aus eduMFA per API und schreibt einen CSV-Report."
    )
    parser.add_argument("--url", help="Basis-URL der eduMFA-Instanz")
    parser.add_argument("--user", help="Admin-Benutzername")
    parser.add_argument("--password", help="Admin-Passwort")
    return parser.parse_args()

def authenticate(url, user, password):
    #Authentifizierung der User, der die Abfrage macht
    url = url + "/auth"
    payload = {"username":user,"password":password}
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        return response.json()["result"]["value"]["token"]
    else:
        print(f"Fehler: {response.status_code}")
    
def fetch_tokens(url, token):
    url = url + "/token"
    header = {"Authorization":token}
    response = requests.get(url, headers=header)
    return response.json()["result"]["value"]["tokens"]

# 
def build_report(tokens):
    by_user = defaultdict(list)
    for t in tokens:
        by_user[(t["username"], t["user_realm"])].append(t)
    report = []
    for (username, realm), user_tokens in sorted(by_user.items()):
        report.append({
            "username": username,
            "realm": realm,
            "anzahl_token": len(user_tokens),
            "anzahl_nutzungen_gesamt": sum(int(x["info"].get("count_auth_success", 0)) for x in user_tokens),
            "tokens": [
                {"serial": x.get("serial"),
                 "tokentype": x.get("tokentype"),
                 "count_auth_success": int(x["info"].get("count_auth_success", 0))}
                for x in user_tokens],
        })
    return report


def write_csv(report):
    path = "csv_reports"
    os.makedirs(path, exist_ok=True)
    filename = "token_report_" + time.strftime('%Y%m%d_%H%M%S') +".csv"
    file = os.path.join(path,filename)
    print(filename)
    fieldnames = ["username", "realm", "anzahl_token", "anzahl_nutzungen_gesamt",
                  "serial", "tokentype", "count_auth_success"]
    with open(file, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for entry in report:
            for t in entry["tokens"]:
                writer.writerow({
                "username": entry["username"],
                "realm": entry["realm"],
                "anzahl_token": entry["anzahl_token"],
                "anzahl_nutzungen_gesamt": entry["anzahl_nutzungen_gesamt"],
                "serial": t["serial"],
                "tokentype": t["tokentype"],
                "count_auth_success": t["count_auth_success"],
            })

def main():
    args = parse_args()                      
    url = args.url
    user = args.user
    password = args.password
    token = authenticate(url, user, password)  
    tokens = fetch_tokens(url, token)           
    report = build_report(tokens) 
    print (report)       
    write_csv(report)                           

if __name__ == "__main__":
    main()