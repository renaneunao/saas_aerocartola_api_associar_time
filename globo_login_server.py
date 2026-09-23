"""Backend local para autenticar uma conta Globo com um P1 fornecido pelo hCaptcha."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlencode, urljoin, urlparse

import requests
import urllib3
from flask import Flask, jsonify, request
from dotenv import load_dotenv


load_dotenv()


AUTHENTICATE_URL = "https://authx-api.globoid.globo.com/v1/auth/authenticate"
OIDC_AUTH_URL = (
    "https://goidc.globo.com/auth/realms/globo.com/"
    "protocol/openid-connect/auth"
)
OIDC_CONFIRM_URL = (
    "https://goidc.globo.com/auth/realms/globo.com/protocol/openid-connect/confirm"
)
OIDC_TOKEN_URL = (
    "https://goidc.globo.com/auth/realms/globo.com/protocol/openid-connect/token"
)
OIDC_USERINFO_URL = (
    "https://goidc.globo.com/auth/realms/globo.com/protocol/openid-connect/userinfo"
)
CLIENT_ID = "barra@apps.globoid"
REDIRECT_URI = "https://www.globo.com/login-callback.ghtml"
SERVICE_ID = 6870
HOME_URL = "https://www.globo.com/"
SERVICE_URL = f"https://authx-api.globoid.globo.com/v1/service/{SERVICE_ID}"
FEATURE_FLAGS_URL = "https://authx-api.globoid.globo.com/v1/feature-flags/evaluate"
SAVE_REDIRECT_URL = "https://authx-api.globoid.globo.com/v1/auth/save-redirect-url"
AUTHX_HOST = "authx.globoid.globo.com"
GLOBO_TEAM_INFO_URL = "https://api.cartola.globo.com/auth/time/info"
SITE_ORIGINS = {
    origin.strip().rstrip("/")
    for origin in os.getenv(
        "GLOBO_SITE_ORIGINS",
        "http://localhost:9000,http://127.0.0.1:9000,http://[::1]:9000",
    ).split(",")
    if origin.strip()
}
VERIFY_TLS = os.getenv("GLOBO_VERIFY_TLS", "1").lower() in {"1", "true", "yes"}
GATEWAY_SHARED_SECRET = os.getenv("GATEWAY_SHARED_SECRET", "").strip()
POSTGRES_CONFIG = {
    "host": os.getenv("POSTGRES_HOST", "").strip(),
    "port": int(os.getenv("POSTGRES_PORT", "5432")),
    "user": os.getenv("POSTGRES_USER", "").strip(),
    "password": os.getenv("POSTGRES_PASSWORD", ""),
    "database": os.getenv("POSTGRES_DB", "").strip(),
}

if not VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


app = Flask(__name__)


class GloboLoginError(RuntimeError):
    """Erro seguro para devolver ao frontend sem vazar credenciais ou tokens."""


class GatewayStorageError(RuntimeError):
    """Falha de configuração ou persistência no banco do gateway."""


def _trace(trace: list[str] | None, message: str) -> None:
    if trace is not None:
        trace.append(message)
    app.logger.info(message)


def _safe_response_summary(response: requests.Response) -> str:
    summary = re.sub(r"\s+", " ", response.text).strip()
    summary = re.sub(r"P1_[A-Za-z0-9._-]+", "<redacted-p1>", summary)
    summary = re.sub(r"Bearer\s+\S+", "Bearer <redacted-token>", summary, flags=re.IGNORECASE)
    summary = re.sub(
        r"(?i)(password|captcha|access_token|refresh_token|id_token|code_verifier)\s*[:=]\s*[^,;&\s<]+",
        r"\1=<redacted>",
        summary,
    )
    return summary[:500]


def _url_summary(value: str) -> str:
    parsed = urlparse(value)
    query_keys = sorted(parse_qs(parsed.query).keys())
    suffix = ", ".join(query_keys) if query_keys else "nenhuma"
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path} (query keys: {suffix})"


@dataclass
class PkceContext:
    state: str
    nonce: str
    code_verifier: str
    code_challenge: str
    tab_id: str
    finish_url: str


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _new_pkce_context() -> PkceContext:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    while True:
        code_verifier = _b64url(secrets.token_bytes(64))
        code_challenge = _b64url(hashlib.sha256(code_verifier.encode()).digest())
        if "_" not in code_challenge:
            break
    state = "".join(secrets.choice(alphabet) for _ in range(22))
    nonce = "".join(secrets.choice(alphabet) for _ in range(22))
    tab_id = "".join(
        secrets.choice(alphabet + "-") for _ in range(10)
    )
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
    finish_url = f"{OIDC_CONFIRM_URL}?{urlencode(params, safe='@:/')}"
    return PkceContext(
        state,
        nonce,
        code_verifier,
        code_challenge,
        tab_id,
        finish_url,
    )


def _headers(context: PkceContext) -> dict[str, str]:
    return {
        "accept": "application/json, text/plain, */*",
        "accept-language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
        "content-type": "application/json",
        "priority": "u=1, i",
        "x-finish-url": quote(context.finish_url, safe=""),
    }


def _new_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "accept-language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
            "user-agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/153.0.0.0 Safari/537.36"
            ),
        }
    )
    return session


def _cookie_names(session: requests.Session) -> list[str]:
    return sorted({cookie.name for cookie in session.cookies})


def _set_cookie_names(response: requests.Response) -> list[str]:
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
        name = value.split(";", 1)[0].split("=", 1)[0].strip()
        if name:
            names.add(name)
    return sorted(names)


def _trace_cookie_response(
    trace: list[str],
    label: str,
    response: requests.Response,
    session: requests.Session,
) -> None:
    set_cookie = ",".join(_set_cookie_names(response)) or "(nenhum)"
    cookies = ",".join(_cookie_names(session)) or "(nenhum)"
    _trace(trace, f"{label}: Set-Cookie names={set_cookie}; sessão={cookies}")


def _oidc_authorize_url(context: PkceContext) -> str:
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "openid profile",
        "state": context.state,
        "nonce": context.nonce,
        "code_challenge": context.code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{OIDC_AUTH_URL}?{urlencode(params)}"


def _capture_real_oidc_redirect(
    response: requests.Response,
    context: PkceContext,
) -> str:
    location = response.headers.get("location", "")
    if not location:
        raise GloboLoginError("O endpoint OIDC não retornou redirect para authx.")

    location_url = urljoin(response.url, location)
    parsed = urlparse(location_url)
    raw_nested = parsed.query.partition("url=")[2]
    actual_oidc_url = unquote(raw_nested)
    actual = urlparse(actual_oidc_url)
    if (
        parsed.netloc != AUTHX_HOST
        or parsed.path != f"/{SERVICE_ID}/login"
        or actual.netloc != "goidc.globo.com"
        or actual.path != "/auth/realms/globo.com/protocol/openid-connect/confirm"
    ):
        raise GloboLoginError("Redirecionamento OIDC/authx inesperado.")

    query = parse_qs(actual.query)
    if query.get("state", [""])[0] != context.state:
        raise GloboLoginError("O redirect OIDC retornou state incompatível.")
    return actual_oidc_url


def _bootstrap_session(
    session: requests.Session,
    context: PkceContext,
    trace: list[str],
) -> str:
    """Reproduz o bootstrap observado no navegador, sem enviar o P1."""
    page_headers = {
        "accept": "text/html,application/xhtml+xml,application/json",
        "referer": HOME_URL,
    }
    api_headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
        "content-type": "application/json",
        "priority": "u=1, i",
    }

    home_response = session.get(
        HOME_URL,
        headers={"accept": "text/html,application/xhtml+xml"},
        allow_redirects=True,
        timeout=30,
        verify=VERIFY_TLS,
    )
    _trace(trace, f"bootstrap home: HTTP {home_response.status_code}")

    authorize_response = session.get(
        _oidc_authorize_url(context),
        headers={"accept": "text/html,application/xhtml+xml"},
        allow_redirects=False,
        timeout=30,
        verify=VERIFY_TLS,
    )
    _trace(trace, f"bootstrap oidc-auth: HTTP {authorize_response.status_code}")
    authx_location = authorize_response.headers.get("location", "")
    actual_oidc_url = _capture_real_oidc_redirect(authorize_response, context)
    context.finish_url = actual_oidc_url
    _trace(trace, "bootstrap redirect OIDC real capturado: sim")

    login_page = session.get(
        authx_location,
        headers=page_headers,
        allow_redirects=True,
        timeout=30,
        verify=VERIFY_TLS,
    )
    _trace(trace, f"bootstrap login-page: HTTP {login_page.status_code}")
    _trace_cookie_response(trace, "bootstrap login-page", login_page, session)
    if not login_page.ok:
        raise GloboLoginError("A página inicial do serviço não foi carregada.")

    service_response = session.get(
        SERVICE_URL,
        headers=api_headers,
        timeout=30,
        verify=VERIFY_TLS,
    )
    _trace(trace, f"bootstrap service: HTTP {service_response.status_code}")
    if not service_response.ok:
        raise GloboLoginError("A configuração do serviço não foi carregada.")

    flags_response = session.post(
        FEATURE_FLAGS_URL,
        headers=api_headers,
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
    _trace(trace, f"bootstrap feature-flags: HTTP {flags_response.status_code}")
    if not flags_response.ok:
        raise GloboLoginError("A avaliação das feature flags não foi aceita.")

    save_redirect_response = session.post(
        SAVE_REDIRECT_URL,
        headers=api_headers,
        json={"redirectUrl": actual_oidc_url},
        timeout=30,
        verify=VERIFY_TLS,
    )
    _trace(
        trace,
        f"bootstrap save-redirect-url: HTTP {save_redirect_response.status_code}",
    )
    if not save_redirect_response.ok:
        raise GloboLoginError("O registro do redirect OIDC não foi aceito.")

    return actual_oidc_url


def _json(
    response: requests.Response,
    step: str,
    trace: list[str] | None = None,
) -> dict[str, Any]:
    _trace(trace, f"{step}: HTTP {response.status_code}")
    try:
        data = response.json()
    except ValueError as exc:
        raise GloboLoginError(f"{step} retornou uma resposta inválida.") from exc
    if not response.ok:
        message = data.get("message", "Forbidden") if isinstance(data, dict) else "Forbidden"
        _trace(trace, f"{step}: mensagem do serviço: {message}")
        raise GloboLoginError(f"{step} falhou com HTTP {response.status_code}: {message}")
    if not isinstance(data, dict):
        raise GloboLoginError(f"{step} retornou um formato inesperado.")
    return data


def _authorization_code(
    response: requests.Response,
    expected_state: str,
    trace: list[str] | None = None,
) -> str:
    candidates = [response.url]
    location = response.headers.get("location")
    if location:
        candidates.append(urljoin(response.url, location))

    diagnostic_url = candidates[-1]
    diagnostic_parsed = urlparse(diagnostic_url)
    diagnostic_query = parse_qs(diagnostic_parsed.query)
    diagnostic = (
        "OIDC redirect: "
        f"HTTP {response.status_code}; host={diagnostic_parsed.netloc}; "
        f"path={diagnostic_parsed.path}; location={bool(location)}; "
        f"code={bool(diagnostic_query.get('code'))}; "
        f"state={bool(diagnostic_query.get('state'))}; "
        f"state_match={bool(diagnostic_query.get('state', [''])[0] == expected_state)}"
    )
    _trace(trace, diagnostic)
    app.logger.warning(
        "OIDC redirect: http=%s host=%s path=%s location=%s code=%s state=%s state_match=%s",
        response.status_code,
        diagnostic_parsed.netloc,
        diagnostic_parsed.path,
        bool(location),
        bool(diagnostic_query.get("code")),
        bool(diagnostic_query.get("state")),
        bool(diagnostic_query.get("state", [""])[0] == expected_state),
    )
    if response.status_code >= 400:
        body_summary = _safe_response_summary(response)
        if body_summary:
            _trace(trace, f"OIDC redirect body (sanitizado): {body_summary}")

    for candidate in candidates:
        query = parse_qs(urlparse(candidate).query)
        code = query.get("code", [""])[0]
        state = query.get("state", [""])[0]
        if code and state == expected_state:
            return code
    raise GloboLoginError("O redirect não trouxe um authorization code válido.")


def _authenticate_with_session(
    email: str,
    password: str,
    captcha: str,
    trace: list[str],
) -> tuple[requests.Session, PkceContext, str]:
    """Executa o bootstrap sem P1 e depois authenticate na mesma sessão."""
    context = _new_pkce_context()
    session = _new_session()

    _trace(trace, "ETAPA 00: contexto OIDC/PKCE criado.")
    _trace(trace, "ETAPA 03: iniciando bootstrap sem P1.")
    oidc_redirect = _bootstrap_session(session, context, trace)
    _trace(trace, "ETAPA 03: enviando auth/authenticate; P1 usado uma vez.")

    auth_response = session.post(
        AUTHENTICATE_URL,
        json={
            "captcha": captcha,
            "email": email,
            "password": password,
            "serviceId": SERVICE_ID,
            "finishGloboAdsMigration": False,
        },
        headers=_headers(context),
        timeout=30,
        verify=VERIFY_TLS,
    )
    auth_data = _json(auth_response, "auth/authenticate", trace)
    auth_status = auth_data.get("status", "ausente")
    _trace(trace, f"ETAPA 03: status retornado={auth_status}.")
    if auth_status != "authenticated":
        raise GloboLoginError("A conta não foi autenticada.")

    response_redirect = auth_data.get("oidcRedirectUrl")
    if isinstance(response_redirect, str) and response_redirect:
        oidc_redirect = response_redirect
        context.finish_url = response_redirect
    if not oidc_redirect:
        raise GloboLoginError("A autenticação não trouxe redirect OIDC válido.")
    _trace(trace, f"ETAPA 03: redirect OIDC preparado: {_url_summary(oidc_redirect)}.")
    return session, context, oidc_redirect


def _provision_url(oidc_url: str) -> str:
    return (
        f"https://login.globo.com/provisionamento/{SERVICE_ID}?url="
        + quote(oidc_url, safe="")
    )


def _finish_url(oidc_url: str) -> str:
    return (
        f"https://login.globo.com/login/{SERVICE_ID}/finish?url="
        + quote(oidc_url, safe="")
    )


def _capture_authorization_code(
    session: requests.Session,
    context: PkceContext,
    oidc_redirect: str,
    trace: list[str],
) -> str:
    """Executa provisionamento, finish e confirm na ordem observada."""
    _trace(trace, "ETAPA 04: iniciando provisionamento OIDC na mesma sessão.")
    provision_response = session.get(
        _provision_url(oidc_redirect),
        headers={
            "accept": "text/html,application/xhtml+xml,application/json",
            "referer": "https://authx.globoid.globo.com/",
        },
        allow_redirects=False,
        timeout=30,
        verify=VERIFY_TLS,
    )
    _trace(trace, f"provisionamento: HTTP {provision_response.status_code}")
    _trace_cookie_response(trace, "provisionamento", provision_response, session)
    location = provision_response.headers.get("location", "")
    if not location:
        raise GloboLoginError("O provisionamento não retornou a finalização OIDC.")

    finish_url = urljoin(provision_response.url, location)
    finish_parsed = urlparse(finish_url)
    if finish_parsed.netloc != "login.globo.com" or finish_parsed.path != f"/login/{SERVICE_ID}/finish":
        raise GloboLoginError("A URL de finalização OIDC é inesperada.")
    _trace(trace, f"finalização: {_url_summary(finish_url)}")

    finish_response = session.get(
        finish_url,
        headers={
            "accept": "text/html,application/xhtml+xml,application/json",
            "referer": provision_response.url,
        },
        allow_redirects=False,
        timeout=30,
        verify=VERIFY_TLS,
    )
    _trace(trace, f"finish: HTTP {finish_response.status_code}")
    _trace_cookie_response(trace, "finish", finish_response, session)
    if finish_response.status_code >= 400:
        raise GloboLoginError("A finalização OIDC foi rejeitada.")

    _trace(trace, "ETAPA 04: consultando confirm OIDC após a finalização.")
    confirm_response = session.get(
        oidc_redirect,
        headers={
            "accept": "text/html,application/xhtml+xml,application/json",
            "referer": finish_url,
        },
        allow_redirects=False,
        timeout=30,
        verify=VERIFY_TLS,
    )
    _trace_cookie_response(trace, "OIDC confirm", confirm_response, session)
    code = _authorization_code(confirm_response, context.state, trace)
    _trace(trace, "ETAPA 04: authorization code capturado (valor oculto).")
    return code


def _exchange_code_for_tokens(
    code: str,
    context: PkceContext,
    trace: list[str],
) -> dict[str, Any]:
    _trace(trace, "ETAPA 05: authorization code recebido; solicitando token OIDC.")
    token_response = requests.post(
        OIDC_TOKEN_URL,
        data={
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "code": code,
            "code_verifier": context.code_verifier,
        },
        headers={
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
            "user-agent": "globo-local-login/1.0",
        },
        timeout=30,
        verify=VERIFY_TLS,
    )
    token_data = _json(token_response, "OIDC token", trace)
    access_token = token_data.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise GloboLoginError("A resposta OIDC não trouxe access_token.")
    _trace(trace, "ETAPA 05: token OIDC recebido (valor oculto).")
    return token_data


def _get_userinfo(access_token: str, trace: list[str]) -> dict[str, Any]:
    _trace(trace, "ETAPA 06: consultando OIDC userinfo.")
    userinfo_response = requests.post(
        OIDC_USERINFO_URL,
        headers={
            "accept": "*/*",
            "content-type": "application/json",
            "authorization": f"Bearer {access_token}",
            "user-agent": "globo-local-login/1.0",
        },
        timeout=30,
        verify=VERIFY_TLS,
    )
    userinfo = _json(userinfo_response, "OIDC userinfo", trace)
    _trace(trace, "ETAPA 06: userinfo recebido.")
    return userinfo


def _login_and_get_auth_result(
    email: str,
    password: str,
    captcha: str,
    trace: list[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Conclui o fluxo e mantém tokens somente no processo do gateway."""
    session, context, oidc_redirect = _authenticate_with_session(
        email,
        password,
        captcha,
        trace,
    )
    code = _capture_authorization_code(session, context, oidc_redirect, trace)
    token_data = _exchange_code_for_tokens(code, context, trace)
    userinfo = _get_userinfo(token_data["access_token"], trace)
    return token_data, userinfo


def _login_and_get_userinfo(
    email: str,
    password: str,
    captcha: str,
    trace: list[str],
) -> dict[str, Any]:
    _, userinfo = _login_and_get_auth_result(email, password, captcha, trace)
    return userinfo


def _internal_request_is_authorized() -> tuple[bool, str | None]:
    configured = GATEWAY_SHARED_SECRET
    if not configured:
        return False, "GATEWAY_SHARED_SECRET não configurado no gateway."
    provided = request.headers.get("X-Gateway-Key", "")
    if not provided or not hmac.compare_digest(provided, configured):
        return False, "Chamada interna não autorizada."
    return True, None


def _cartola_team_info(access_token: str, trace: list[str]) -> dict[str, Any] | None:
    """Busca metadados do time sem registrar o token nos logs."""
    try:
        response = requests.get(
            GLOBO_TEAM_INFO_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
                "User-Agent": "aero-cartola-gateway/1.0",
            },
            timeout=30,
            verify=VERIFY_TLS,
        )
    except requests.RequestException:
        _trace(trace, "metadados do time: falha de comunicação; associação continuará.")
        return None

    _trace(trace, f"metadados do time: HTTP {response.status_code}")
    if not response.ok:
        return None
    try:
        data = response.json()
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _store_team(
    user_id: int,
    access_token: str,
    refresh_token: str,
    id_token: str | None,
    team_name: str | None,
) -> int:
    """Insere na tabela existente; não cria nem altera o schema."""
    missing = [
        key
        for key, value in POSTGRES_CONFIG.items()
        if key != "port" and not value
    ]
    if missing:
        raise GatewayStorageError(
            "Banco do gateway não configurado: " + ", ".join(missing) + "."
        )

    try:
        import psycopg2
    except ImportError as exc:
        raise GatewayStorageError("Dependência psycopg2 não instalada no gateway.") from exc

    connection = None
    try:
        connection = psycopg2.connect(**POSTGRES_CONFIG)
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO acw_teams
                    (user_id, access_token, refresh_token, id_token, team_name)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
                """,
                (user_id, access_token, refresh_token, id_token, team_name),
            )
            row = cursor.fetchone()
        connection.commit()
        if not row:
            raise GatewayStorageError("O banco não retornou o ID do time associado.")
        return int(row[0])
    except GatewayStorageError:
        if connection:
            connection.rollback()
        raise
    except Exception as exc:
        if connection:
            connection.rollback()
        raise GatewayStorageError("Não foi possível gravar o time no banco.") from exc
    finally:
        if connection:
            connection.close()


@app.post("/internal/v1/teams/authenticate")
def internal_associate_team():
    """Autentica e associa um time para uma sessão do web app confiável."""
    authorized, authorization_error = _internal_request_is_authorized()
    if not authorized:
        status = 503 if not GATEWAY_SHARED_SECRET else 401
        return jsonify({"error": authorization_error}), status

    data = request.get_json(silent=True) or {}
    try:
        user_id = int(data.get("user_id"))
    except (TypeError, ValueError):
        user_id = 0

    email = str(data.get("email", "")).strip()
    password = str(data.get("password", ""))
    captcha = str(data.get("captcha", "")).strip()
    team_name = str(data.get("team_name", "")).strip() or None
    trace: list[str] = []

    if user_id <= 0 or not email or not password or not captcha:
        return jsonify({
            "error": "user_id, email, senha e captcha são obrigatórios.",
        }), 400

    try:
        _trace(trace, f"associação iniciada para user_id={user_id}.")
        token_data, userinfo = _login_and_get_auth_result(
            email,
            password,
            captcha,
            trace,
        )
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        id_token = token_data.get("id_token")
        if not isinstance(access_token, str) or not access_token:
            raise GloboLoginError("A autenticação não trouxe access_token.")
        if not isinstance(refresh_token, str) or not refresh_token:
            raise GloboLoginError("A autenticação não trouxe refresh_token.")
        if not isinstance(id_token, str) or not id_token:
            id_token = None

        team_info = _cartola_team_info(access_token, trace)
        time_data = team_info.get("time") if isinstance(team_info, dict) else None
        if not isinstance(time_data, dict):
            time_data = {}
        resolved_team_name = team_name or time_data.get("nome")
        cartola_team_id = time_data.get("id")

        local_team_id = _store_team(
            user_id=user_id,
            access_token=access_token,
            refresh_token=refresh_token,
            id_token=id_token,
            team_name=resolved_team_name,
        )
        _trace(trace, "time gravado em acw_teams; tokens não foram retornados.")

        account_id = None
        if isinstance(userinfo, dict):
            account_id = userinfo.get("globo_id") or userinfo.get("sub")

        return jsonify({
            "ok": True,
            "team_id": local_team_id,
            "team_name": resolved_team_name,
            "cartola_team_id": cartola_team_id,
            "account_id": account_id,
            "logs": trace,
        })
    except requests.RequestException:
        _trace(trace, "Falha de comunicação durante a associação.")
        return jsonify({
            "error": "Falha de comunicação com os serviços de autenticação.",
            "logs": trace,
        }), 502
    except GatewayStorageError as exc:
        _trace(trace, str(exc))
        return jsonify({"error": str(exc), "logs": trace}), 503
    except GloboLoginError as exc:
        _trace(trace, f"Associação encerrada: {exc}")
        return jsonify({"error": str(exc), "logs": trace}), 401


@app.after_request
def _cors(response):
    origin = request.headers.get("Origin", "").rstrip("/")
    if origin in SITE_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    response.headers["Vary"] = "Origin"
    return response


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/globo-login", methods=["POST", "OPTIONS"])
def globo_login():
    if request.method == "OPTIONS":
        return ("", 204)

    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip()
    password = str(data.get("password", ""))
    captcha = str(data.get("captcha", "")).strip()
    trace: list[str] = []

    if not email or not password or not captcha:
        return jsonify({"error": "Informe email, senha e captcha.", "logs": trace}), 400

    try:
        userinfo = _login_and_get_userinfo(email, password, captcha, trace)
    except requests.RequestException:
        app.logger.warning("Falha de comunicação durante o fluxo Globo")
        _trace(trace, "Falha de comunicação com o serviço Globo.")
        return jsonify({"error": "Falha de comunicação com o serviço Globo.", "logs": trace}), 502
    except GloboLoginError as exc:
        app.logger.warning("Fluxo Globo recusado: %s", exc)
        _trace(trace, f"Fluxo encerrado: {exc}")
        return jsonify({"error": str(exc), "logs": trace}), 401

    return jsonify({"ok": True, "userinfo": userinfo, "logs": trace})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=False)
