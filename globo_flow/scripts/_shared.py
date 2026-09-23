"""Utilitários internos para o contexto OIDC compartilhado."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import requests
from requests.cookies import create_cookie


CONTEXT_FILE = Path(__file__).resolve().parents[1] / "json" / "oidc-context.json"
SESSION_FILE = Path(__file__).resolve().parents[1] / "json" / "requests-session.json"


def load_oidc_context() -> dict[str, str]:
    if not CONTEXT_FILE.exists():
        raise RuntimeError(
            f"Contexto ausente: {CONTEXT_FILE}. Execute 00_context.py primeiro."
        )

    try:
        context = json.loads(CONTEXT_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("Não foi possível ler oidc-context.json.") from exc

    required = {
        "state",
        "nonce",
        "code_challenge",
        "code_verifier",
        "oidc_confirm_url",
        "x_finish_url",
    }
    missing = sorted(required.difference(context))
    if missing:
        raise RuntimeError("Contexto incompleto: " + ", ".join(missing))

    verifier = context["code_verifier"]
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    if expected != context["code_challenge"]:
        raise RuntimeError("Contexto inválido: PKCE não corresponde.")

    query = parse_qs(urlparse(context["oidc_confirm_url"]).query)
    if query.get("state", [""])[0] != context["state"]:
        raise RuntimeError("Contexto inválido: state não corresponde à URL OIDC.")
    finish_url = unquote(context["x_finish_url"])
    # parse_qs pode transformar o '+' interno da query OIDC em espaço.
    if finish_url.replace(" ", "+") != context["oidc_confirm_url"].replace(" ", "+"):
        raise RuntimeError("Contexto inválido: x-finish-url não corresponde à URL OIDC.")

    return context


def save_oidc_context(context: dict[str, str]) -> None:
    CONTEXT_FILE.write_text(
        json.dumps(context, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def new_http_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "accept-language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
        }
    )
    return session


def save_http_session(session: requests.Session) -> None:
    cookies = []
    for cookie in session.cookies:
        cookies.append(
            {
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain,
                "path": cookie.path,
                "secure": cookie.secure,
                "expires": cookie.expires,
            }
        )
    SESSION_FILE.write_text(
        json.dumps({"cookies": cookies}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def load_http_session() -> requests.Session:
    if not SESSION_FILE.exists():
        raise RuntimeError(
            f"Sessão ausente: {SESSION_FILE}. Execute main.py primeiro."
        )
    try:
        data = json.loads(SESSION_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("Não foi possível ler requests-session.json.") from exc

    session = new_http_session()
    for item in data.get("cookies", []):
        session.cookies.set_cookie(
            create_cookie(
                name=item["name"],
                value=item["value"],
                domain=item.get("domain", ""),
                path=item.get("path", "/"),
                secure=bool(item.get("secure", False)),
                expires=item.get("expires"),
            )
        )
    return session
