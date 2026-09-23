"""Executa somente o POST de autenticação da Conta Globo."""

from __future__ import annotations

import json
import os
import warnings
from datetime import datetime, timezone
from pathlib import Path

import requests
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse
from dotenv import load_dotenv

from urllib3.exceptions import InsecureRequestWarning

from _shared import (
    load_oidc_context,
    new_http_session,
    save_http_session,
    save_oidc_context,
)


ENV_FILE = Path(__file__).resolve().parents[2] / ".env"
load_dotenv(ENV_FILE)

# E-mail e senha vêm do .env. O P1 é fornecido exclusivamente pelo main.py
# por meio da variável de ambiente interna do subprocesso.
EMAIL = os.getenv("GLOBO_EMAIL", "").strip()
PASSWORD = os.getenv("GLOBO_PASSWORD", "")
P1 = os.environ.get("GLOBO_P1", "")

URL = "https://authx-api.globoid.globo.com/v1/auth/authenticate"
HOME_URL = "https://www.globo.com/"
OIDC_AUTH_URL = "https://goidc.globo.com/auth/realms/globo.com/protocol/openid-connect/auth"
SERVICE_URL = "https://authx-api.globoid.globo.com/v1/service/6870"
FEATURE_FLAGS_URL = "https://authx-api.globoid.globo.com/v1/feature-flags/evaluate"
SAVE_REDIRECT_URL = "https://authx-api.globoid.globo.com/v1/auth/save-redirect-url"
SERVICE_ID = 6870
VERIFY_TLS = False
AUTH_RESULT_FILE = Path(__file__).resolve().parents[1] / "json" / "authenticate-response.json"


def _cookie_names(session: requests.Session) -> list[str]:
    return sorted({cookie.name for cookie in session.cookies})


def _error_summary(response: requests.Response) -> str:
    try:
        data = response.json()
    except ValueError:
        return f"body_length={len(response.content)}"
    if isinstance(data, dict):
        safe = {}
        for key in ("code", "error", "message", "status"):
            value = data.get(key)
            if isinstance(value, (str, int, float, bool)):
                safe[key] = value
        return f"keys={','.join(sorted(data))}; details={json.dumps(safe, ensure_ascii=False)}"
    return f"json_type={type(data).__name__}"


def _oidc_authorize_url(context: dict[str, str]) -> str:
    params = {
        "response_type": "code",
        "client_id": context["client_id"],
        "redirect_uri": context["redirect_uri"],
        "scope": "openid profile",
        "state": context["state"],
        "nonce": context["nonce"],
        "code_challenge": context["code_challenge"],
        "code_challenge_method": context["code_challenge_method"],
    }
    return f"{OIDC_AUTH_URL}?{urlencode(params)}"


def main() -> int:
    if not PASSWORD:
        print("Preencha o campo PASSWORD.")
        return 1
    if not P1.strip():
        print("Preencha o campo P1.")
        return 1

    try:
        context = load_oidc_context()
        # Cada execução começa sem cookies de uma autenticação anterior.
        # O cookie jar desta execução é salvo após o POST de authenticate e
        # consumido pela etapa 04.
        session = new_http_session()
    except RuntimeError as exc:
        print(f"Contexto OIDC: {exc}")
        return 1

    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
        "content-type": "application/json",
        "priority": "u=1, i",
    }

    # O navegador faz este bootstrap sem P1. A chamada validate também aparece
    # no navegador, mas pode retornar 404 e não bloqueia o fluxo.
    page_headers = {
        "accept": "text/html,application/xhtml+xml,application/json",
        "referer": "https://www.globo.com/",
    }
    bootstrap_headers = {
        key: value for key, value in headers.items() if key != "x-finish-url"
    }
    print("cookies antes do bootstrap: " + (", ".join(_cookie_names(session)) or "nenhum"))
    try:
        home_response = session.get(
            HOME_URL,
            headers={"accept": "text/html,application/xhtml+xml"},
            allow_redirects=True,
            timeout=30,
            verify=VERIFY_TLS,
        )
        print(f"bootstrap home HTTP {home_response.status_code}")
        print("cookies após home: " + (", ".join(_cookie_names(session)) or "nenhum"))

        oidc_authorize_response = session.get(
            _oidc_authorize_url(context),
            headers={"accept": "text/html,application/xhtml+xml"},
            allow_redirects=False,
            timeout=30,
            verify=VERIFY_TLS,
        )
        print(f"bootstrap oidc-auth HTTP {oidc_authorize_response.status_code}")
        authx_location = oidc_authorize_response.headers.get("location", "")
        if not authx_location:
            print("O endpoint OIDC não retornou o redirecionamento para authx.")
            return 1
        authx_parsed = urlparse(authx_location)
        raw_url = authx_parsed.query.partition("url=")[2]
        actual_oidc_url = unquote(raw_url)
        if (
            authx_parsed.netloc != "authx.globoid.globo.com"
            or authx_parsed.path != f"/{SERVICE_ID}/login"
            or not actual_oidc_url
        ):
            print("Redirecionamento OIDC/authx inesperado.")
            return 1

        context["authx_login_url"] = authx_location
        context["oidc_confirm_url"] = actual_oidc_url
        context["x_finish_url"] = quote(actual_oidc_url, safe="")
        save_oidc_context(context)
        headers["x-finish-url"] = context["x_finish_url"]
        bootstrap_headers["x-finish-url"] = context["x_finish_url"]
        bootstrap_headers.pop("x-finish-url", None)
        print("redirect OIDC real capturado: sim")

        login_page = session.get(
            authx_location,
            headers=page_headers,
            allow_redirects=True,
            timeout=30,
            verify=VERIFY_TLS,
        )
        print(f"bootstrap login-page HTTP {login_page.status_code}")
        print("cookies após login-page: " + (", ".join(_cookie_names(session)) or "nenhum"))
        if not login_page.ok:
            print("A página inicial do serviço não foi carregada.")
            return 1

        service_response = session.get(
            SERVICE_URL,
            headers=bootstrap_headers,
            timeout=30,
            verify=VERIFY_TLS,
        )
        print(f"bootstrap service HTTP {service_response.status_code}")
        if not service_response.ok:
            print("A configuração do serviço não foi carregada.")
            return 1

        flags_response = session.post(
            FEATURE_FLAGS_URL,
            headers=bootstrap_headers,
            json={
                "flags": [
                    {
                        "name": "authentication_one_tap",
                        "defaultValue": False,
                        "attributes": {"serviceID": SERVICE_ID},
                    }
                ]
            },
            timeout=30,
            verify=VERIFY_TLS,
        )
        print(f"bootstrap feature-flags HTTP {flags_response.status_code}")
        if not flags_response.ok:
            print("A avaliação das feature flags não foi aceita.")
            return 1

        save_redirect_response = session.post(
            SAVE_REDIRECT_URL,
            headers=bootstrap_headers,
            json={"redirectUrl": context["oidc_confirm_url"]},
            timeout=30,
            verify=VERIFY_TLS,
        )
        print(f"bootstrap save-redirect-url HTTP {save_redirect_response.status_code}")
        if not save_redirect_response.ok:
            print("save-redirect-url diagnóstico: " + _error_summary(save_redirect_response))
            print(
                "O registro do redirect OIDC não foi aceito; "
                "nenhum P1 foi enviado. A sessão precisa dos cookies de contexto "
                "usados pelo navegador."
            )
            return 1
    except requests.RequestException as exc:
        print(f"Falha no bootstrap da sessão: {exc}")
        return 1

    payload = {
        "captcha": P1,
        "email": EMAIL,
        "password": PASSWORD,
        "serviceId": SERVICE_ID,
        "finishGloboAdsMigration": False,
    }

    if not VERIFY_TLS:
        warnings.filterwarnings("ignore", category=InsecureRequestWarning)

    try:
        response = session.post(
            URL,
            headers=headers,
            json=payload,
            timeout=30,
            verify=VERIFY_TLS,
        )
    except requests.RequestException as exc:
        print(f"Falha na requisição: {exc}")
        return 1

    print(f"HTTP {response.status_code}")
    if not response.ok:
        print("authenticate diagnóstico: " + _error_summary(response))
        print("Resposta de authenticate não foi aceita.")
        return 1

    try:
        auth_data = response.json()
    except ValueError:
        print("A resposta de authenticate não é JSON válido.")
        return 1

    oidc_redirect = auth_data.get("oidcRedirectUrl")
    redirect_value = auth_data.get("redirect")
    AUTH_RESULT_FILE.write_text(
        json.dumps(
            {
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "status": auth_data.get("status"),
                "response_keys": sorted(auth_data.keys()),
                "oidcRedirectUrl": oidc_redirect if isinstance(oidc_redirect, str) else "",
                "redirect": redirect_value if isinstance(redirect_value, str) else "",
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    save_http_session(session)

    print("ETAPA 3 concluída: authenticate aceitou a requisição.")
    print("status: " + str(auth_data.get("status", "ausente")))
    print("redirect OIDC retornado: " + ("presente" if isinstance(oidc_redirect, str) and oidc_redirect else "ausente"))
    print("redirect alternativo retornado: " + ("presente" if isinstance(redirect_value, str) and redirect_value else "ausente"))
    print("campos retornados: " + ", ".join(sorted(auth_data.keys())))
    print("próxima etapa: executar 04_oidc_callback.py para capturar e validar code/state.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
