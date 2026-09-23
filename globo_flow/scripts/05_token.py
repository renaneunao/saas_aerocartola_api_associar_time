"""Etapa 5: troca o authorization code por tokens OIDC."""

from __future__ import annotations

import json
import warnings
from datetime import datetime, timezone
from pathlib import Path

import requests
from urllib3.exceptions import InsecureRequestWarning

from _shared import load_oidc_context


CALLBACK_FILE = Path(__file__).resolve().parents[1] / "json" / "oidc-callback.json"
TOKEN_FILE = Path(__file__).resolve().parents[1] / "json" / "token.json"
TOKEN_URL = (
    "https://goidc.globo.com/auth/realms/globo.com/"
    "protocol/openid-connect/token"
)
CLIENT_ID = "barra@apps.globoid"
VERIFY_TLS = False


def main() -> int:
    if not CALLBACK_FILE.exists():
        print(f"Callback não encontrado: {CALLBACK_FILE}")
        return 1

    try:
        callback = json.loads(CALLBACK_FILE.read_text(encoding="utf-8"))
        context = load_oidc_context()
    except (OSError, json.JSONDecodeError, RuntimeError) as exc:
        print(f"Falha ao carregar contexto: {exc}")
        return 1

    code = callback.get("code")
    state = callback.get("state")
    if not isinstance(code, str) or not code:
        print("Callback sem authorization code.")
        return 1
    if state != context["state"]:
        print("Callback rejeitado: state não corresponde ao contexto atual.")
        return 1

    if not VERIFY_TLS:
        warnings.filterwarnings("ignore", category=InsecureRequestWarning)

    try:
        response = requests.post(
            TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "redirect_uri": context["redirect_uri"],
                "code": code,
                "code_verifier": context["code_verifier"],
            },
            headers={
                "accept": "application/json",
                "content-type": "application/x-www-form-urlencoded",
            },
            timeout=30,
            verify=VERIFY_TLS,
        )
    except requests.RequestException as exc:
        print(f"Falha na troca do código: {exc}")
        return 1

    print(f"TOKEN HTTP {response.status_code}")
    if not response.ok:
        print("A troca do código não foi aceita.")
        return 1

    try:
        token_data = response.json()
    except ValueError:
        print("Resposta de token não é JSON válido.")
        return 1

    token_data["captured_at"] = datetime.now(timezone.utc).isoformat()
    TOKEN_FILE.write_text(
        json.dumps(token_data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    fields = sorted(key for key, value in token_data.items() if value is not None)
    print("campos salvos: " + ", ".join(fields))
    print(f"arquivo: {TOKEN_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
