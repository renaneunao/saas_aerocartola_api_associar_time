"""Etapa 0: gera e valida o contexto OIDC/PKCE de uma execução.

Não faz chamadas de rede e não recebe e-mail, senha ou P1.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import string
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlencode


CLIENT_ID = "barra@apps.globoid"
SERVICE_ID = 6870
REDIRECT_URI = "https://www.globo.com/login-callback.ghtml"
OIDC_CONFIRM_URL = (
    "https://goidc.globo.com/auth/realms/globo.com/protocol/openid-connect/confirm"
)
AUTHX_LOGIN_URL = f"https://authx.globoid.globo.com/{SERVICE_ID}/login"
OUTPUT_FILE = Path(__file__).resolve().parents[1] / "json" / "oidc-context.json"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _alphanumeric(length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _from_alphabet(length: int, alphabet: str) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _build_context() -> dict[str, str]:
    while True:
        code_verifier = _b64url(secrets.token_bytes(64))
        code_challenge = _b64url(hashlib.sha256(code_verifier.encode()).digest())
        if "_" not in code_challenge:
            break
    # O fluxo real do navegador usa state/nonce de 22 caracteres.
    state = _alphanumeric(22)
    nonce = _alphanumeric(22)
    tab_id = _from_alphabet(10, string.ascii_letters + string.digits + "-")

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "state": state,
        "tab_id": tab_id,
        "scope": "openid profile",
        "nonce": nonce,
        "code_challenge_method": "S256",
        "code_challenge": code_challenge,
        "redirect_uri": REDIRECT_URI,
        "prompt": "none",
    }
    # O navegador mantém @ e a URL do callback sem encoding na query interna.
    # A URL externa do authx continua recebendo o encoding completo abaixo.
    oidc_url = f"{OIDC_CONFIRM_URL}?{urlencode(params, safe='@:/')}"

    return {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "client_id": CLIENT_ID,
        "service_id": str(SERVICE_ID),
        "redirect_uri": REDIRECT_URI,
        "state": state,
        "nonce": nonce,
        "tab_id": tab_id,
        "code_challenge_method": "S256",
        "code_challenge": code_challenge,
        "code_verifier": code_verifier,
        "oidc_confirm_url": oidc_url,
        "x_finish_url": quote(oidc_url, safe=""),
        "authx_login_url": f"{AUTHX_LOGIN_URL}?url={quote(oidc_url, safe='')}",
    }


def _validate(context: dict[str, str]) -> None:
    verifier = context["code_verifier"]
    expected = _b64url(hashlib.sha256(verifier.encode()).digest())
    if expected != context["code_challenge"]:
        raise RuntimeError("PKCE inválido: code_challenge não corresponde ao verifier.")
    if len(verifier) < 43 or len(verifier) > 128:
        raise RuntimeError("PKCE inválido: tamanho do code_verifier fora do padrão.")
    if len(context["state"]) != 22 or len(context["nonce"]) != 22:
        raise RuntimeError("OIDC inválido: state/nonce fora do formato do navegador.")
    if len(context["tab_id"]) != 10:
        raise RuntimeError("OIDC inválido: tab_id fora do formato do navegador.")
    required = {
        "client_id",
        "state",
        "nonce",
        "tab_id",
        "code_challenge",
        "code_verifier",
        "oidc_confirm_url",
        "x_finish_url",
        "authx_login_url",
    }
    missing = sorted(required.difference(context))
    if missing:
        raise RuntimeError("Contexto incompleto: " + ", ".join(missing))


def main() -> int:
    context = _build_context()
    _validate(context)
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(
        json.dumps(context, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print("Contexto OIDC criado e validado.")
    print(f"arquivo: {OUTPUT_FILE}")
    print("state: presente")
    print("nonce: presente")
    print("code_challenge: presente")
    print("code_verifier: presente e compatível")
    print("valores dinâmicos: ocultos")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
