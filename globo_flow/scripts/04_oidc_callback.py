"""Etapa 4: obtém o callback OIDC via requests e o valida."""

from __future__ import annotations

import argparse
import json
import os
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, quote, urljoin, urlparse

from urllib3.exceptions import InsecureRequestWarning

from _shared import load_http_session, load_oidc_context, save_http_session


if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")


CALLBACK_HOST = "www.globo.com"
CALLBACK_PATH = "/login-callback.ghtml"
LOGIN_FINISH_HOST = "login.globo.com"
PROVISION_PATH = "/provisionamento/6870"
LOGIN_FINISH_PATH = "/login/6870/finish"
OIDC_HOST = "goidc.globo.com"
OIDC_PATH = "/auth/realms/globo.com/protocol/openid-connect/confirm"
CAPTURE_FILE = Path(__file__).resolve().parents[1] / "json" / "oidc-callback.json"
AUTH_RESULT_FILE = Path(__file__).resolve().parents[1] / "json" / "authenticate-response.json"


def _url_summary(value: str) -> str:
    parsed = urlparse(value)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def _set_cookie_names(response) -> list[str]:
    """Obtém apenas nomes de Set-Cookie, sem expor valores."""
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    values: list[str] = []
    if raw_headers is not None:
        for method_name in ("get_all", "getlist"):
            getter = getattr(raw_headers, method_name, None)
            if callable(getter):
                values.extend(getter("Set-Cookie") or [])
                if values:
                    break
    if not values:
        combined = response.headers.get("Set-Cookie", "")
        if combined:
            values.append(combined)

    names = set()
    for value in values:
        for item in value.split(";")[:1]:
            name = item.split("=", 1)[0].strip()
            if name:
                names.add(name)
    return sorted(names)


def _session_cookie_names(session) -> list[str]:
    return sorted({cookie.name for cookie in session.cookies})


def _print_cookie_diagnostic(label: str, response, session) -> None:
    header_names = _set_cookie_names(response)
    print(
        f"{label}: Set-Cookie names="
        f"{','.join(header_names) if header_names else '(nenhum)'}; "
        f"sessão={','.join(_session_cookie_names(session)) or '(nenhum)'}"
    )


def _oidc_url_from_auth_result(context_url: str) -> str:
    if not AUTH_RESULT_FILE.exists():
        return context_url

    try:
        auth_result = json.loads(AUTH_RESULT_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("Não foi possível ler authenticate-response.json.") from exc

    for key in ("oidcRedirectUrl", "redirect"):
        value = auth_result.get(key)
        if isinstance(value, str) and value:
            return value
    # O front-end usa o redirect salvo no contexto quando authenticate não
    # devolve oidcRedirectUrl. Isso é o comportamento observado no navegador.
    return context_url


def _finish_url(oidc_url: str) -> str:
    return (
        f"https://{LOGIN_FINISH_HOST}{LOGIN_FINISH_PATH}?url="
        + quote(oidc_url, safe="")
    )


def _provision_url(oidc_url: str) -> str:
    return (
        f"https://{LOGIN_FINISH_HOST}{PROVISION_PATH}?url="
        + quote(oidc_url, safe="")
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Valida presença de code/state em uma URL de callback OIDC."
    )
    parser.add_argument("--url", help="URL de callback; o valor nunca é impresso.")
    args = parser.parse_args()

    callback_url = args.url or os.getenv("GLOBO_OIDC_CALLBACK_URL", "").strip()
    if not callback_url:
        try:
            context = load_oidc_context()
            session = load_http_session()
            oidc_url = _oidc_url_from_auth_result(context["oidc_confirm_url"])
            oidc_parsed = urlparse(oidc_url)
            if oidc_parsed.netloc != OIDC_HOST or oidc_parsed.path != OIDC_PATH:
                print(f"Redirect OIDC inesperado: {_url_summary(oidc_url)}")
                return 1

            provision_response = session.get(
                _provision_url(oidc_url),
                headers={
                    "accept": "text/html,application/xhtml+xml,application/json",
                    "referer": "https://authx.globoid.globo.com/",
                },
                allow_redirects=False,
                timeout=30,
                verify=False,
            )
            provision_location = provision_response.headers.get("location")
            print(
                f"provisionamento: HTTP {provision_response.status_code}; "
                f"Location={bool(provision_location)}"
            )
            _print_cookie_diagnostic("provisionamento", provision_response, session)
            if not provision_location:
                print("O provisionamento não retornou a URL de finalização.")
                return 1

            finish_url = urljoin(provision_response.url, provision_location)
            finish_parsed = urlparse(finish_url)
            if (
                finish_parsed.netloc != LOGIN_FINISH_HOST
                or finish_parsed.path != LOGIN_FINISH_PATH
            ):
                print(f"Finalização inesperada: {_url_summary(finish_url)}")
                return 1

            print(f"finalização: {_url_summary(finish_url)}")
            finish_response = session.get(
                finish_url,
                headers={
                    "accept": "text/html,application/xhtml+xml,application/json",
                    "referer": provision_response.url,
                },
                allow_redirects=False,
                timeout=30,
                verify=False,
            )
            print(f"finish HTTP {finish_response.status_code}")
            _print_cookie_diagnostic("finish", finish_response, session)
            if finish_response.status_code >= 400:
                print("A finalização legada foi rejeitada.")
                return 1

            # O navegador chama o confirm OIDC somente depois da finalização.
            # Mantemos redirects desabilitados para capturar o Location.
            response = session.get(
                oidc_url,
                headers={
                    "accept": "text/html,application/xhtml+xml,application/json",
                    "referer": finish_url,
                },
                allow_redirects=False,
                timeout=30,
                verify=False,
            )
            _print_cookie_diagnostic("OIDC confirm", response, session)
            cookie_names = set(_session_cookie_names(session))
            if "GOIDC_SESSION" in cookie_names:
                save_http_session(session)
                print("sessão OIDC atualizada: sim")
            else:
                print("sessão OIDC atualizada: não")

            location = response.headers.get("location")
            candidate = urljoin(response.url, location) if location else response.url
            parsed_candidate = urlparse(candidate)
            print(
                f"OIDC confirm: HTTP {response.status_code}; "
                f"destino={_url_summary(candidate)}; "
                f"Location={bool(location)}"
            )
            if parsed_candidate.netloc == CALLBACK_HOST:
                callback_url = candidate
            else:
                print("O confirm OIDC não retornou o callback da Globo.")
                return 1
        except (OSError, RuntimeError) as exc:
            print(f"Falha ao carregar sessão/contexto: {exc}")
            return 1
        except Exception as exc:
            print(f"Falha ao acessar o redirect OIDC: {exc}")
            return 1

    parsed = urlparse(callback_url)
    query = parse_qs(parsed.query)
    code = query.get("code", [""])[0]
    state = query.get("state", [""])[0]
    expected_state = os.getenv("GLOBO_EXPECTED_STATE", "").strip()
    if not expected_state:
        try:
            expected_state = load_oidc_context()["state"]
        except RuntimeError as exc:
            print(f"Contexto OIDC: {exc}")
            return 1

    print(f"host correto: {parsed.netloc == CALLBACK_HOST}")
    print(f"path correto: {parsed.path == CALLBACK_PATH}")
    print(f"code presente: {bool(code)}")
    print(f"state presente: {bool(state)}")
    if expected_state:
        print(f"state corresponde: {state == expected_state}")

    valid = (
        parsed.netloc == CALLBACK_HOST
        and parsed.path == CALLBACK_PATH
        and bool(code)
        and bool(state)
        and (not expected_state or state == expected_state)
    )
    if not valid:
        return 1

    CAPTURE_FILE.write_text(
        json.dumps(
            {
                "captured_at": datetime.now(timezone.utc).isoformat(),
                "code": code,
                "state": state,
                "redirect_uri": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"callback salvo: {CAPTURE_FILE}")
    print("code/state: presentes e compatíveis")
    return 0


if __name__ == "__main__":
    warnings.filterwarnings("ignore", category=InsecureRequestWarning)
    raise SystemExit(main())
