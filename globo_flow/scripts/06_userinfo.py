"""Etapa 6: consulta userinfo com o access token capturado."""

from __future__ import annotations

import json
import warnings
from datetime import datetime, timezone
from pathlib import Path

import requests
from urllib3.exceptions import InsecureRequestWarning


TOKEN_FILE = Path(__file__).resolve().parents[1] / "json" / "token.json"
USERINFO_FILE = Path(__file__).resolve().parents[1] / "json" / "userinfo.json"
USERINFO_URL = (
    "https://goidc.globo.com/auth/realms/globo.com/"
    "protocol/openid-connect/userinfo"
)
VERIFY_TLS = False


def main() -> int:
    if not TOKEN_FILE.exists():
        print(f"Token não encontrado: {TOKEN_FILE}")
        return 1

    try:
        token_data = json.loads(TOKEN_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Falha ao ler token: {exc}")
        return 1

    access_token = token_data.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        print("token.json não contém access_token.")
        return 1

    if not VERIFY_TLS:
        warnings.filterwarnings("ignore", category=InsecureRequestWarning)

    try:
        response = requests.post(
            USERINFO_URL,
            headers={
                "accept": "application/json",
                "content-type": "application/json",
                "authorization": f"Bearer {access_token}",
            },
            timeout=30,
            verify=VERIFY_TLS,
        )
    except requests.RequestException as exc:
        print(f"Falha na consulta userinfo: {exc}")
        return 1

    print(f"USERINFO HTTP {response.status_code}")
    if not response.ok:
        print("A consulta userinfo não foi aceita.")
        return 1

    try:
        userinfo_data = response.json()
    except ValueError:
        print("Resposta de userinfo não é JSON válido.")
        return 1

    userinfo_data["captured_at"] = datetime.now(timezone.utc).isoformat()
    USERINFO_FILE.write_text(
        json.dumps(userinfo_data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print("campos recebidos: " + ", ".join(sorted(userinfo_data)))
    print(f"arquivo: {USERINFO_FILE}")
    print("valores salvos localmente; não exibidos no console")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
