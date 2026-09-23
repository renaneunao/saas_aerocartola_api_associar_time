"""Orquestra o fluxo completo de autenticação Globo via requests."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from dotenv import load_dotenv


SCRIPTS_DIR = Path(__file__).resolve().parent
WORKSPACE_DIR = SCRIPTS_DIR.parent.parent
ENV_FILE = WORKSPACE_DIR / ".env"
USERINFO_FILE = WORKSPACE_DIR / "globo_flow" / "json" / "userinfo.json"

load_dotenv(ENV_FILE)

STEPS = (
    ("00_context.py", "contexto OIDC/PKCE"),
    ("03_authenticate.py", "autenticação"),
    ("04_oidc_callback.py", "callback OIDC e cookies"),
    ("05_token.py", "troca do code por tokens"),
    ("06_userinfo.py", "userinfo"),
)

HIDDEN_USERINFO_FIELDS = {
    "federated_sid",
    "fs_id",
    "glbid",
    "globo_id",
    "session_state",
    "sid",
    "sub",
}


def run_step(filename: str, label: str, environment: dict[str, str]) -> None:
    print(f"\n=== {label}: {filename} ===")
    result = subprocess.run(
        [sys.executable, str(SCRIPTS_DIR / filename)],
        cwd=WORKSPACE_DIR,
        env=environment,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"\nFluxo interrompido em {filename} (código {result.returncode})."
        )


def print_userinfo() -> None:
    if not USERINFO_FILE.exists():
        print(f"userinfo não encontrado: {USERINFO_FILE}")
        return

    try:
        userinfo = json.loads(USERINFO_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Falha ao ler userinfo: {exc}")
        return

    print("\n=== informações do usuário ===")
    for key in sorted(userinfo):
        if key in HIDDEN_USERINFO_FIELDS:
            print(f"{key}: <oculto; salvo em userinfo.json>")
            continue
        print(f"{key}: {json.dumps(userinfo[key], ensure_ascii=False)}")
    print(f"arquivo completo: {USERINFO_FILE}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Executa o fluxo Globo via requests, sem exibir segredos."
    )
    parser.add_argument(
        "--stop-after",
        choices=[filename.removesuffix(".py") for filename, _ in STEPS],
        help="Para após a etapa informada, útil para testes isolados.",
    )
    args = parser.parse_args()

    p1 = os.getenv("GLOBO_HCAPTCHA_TOKEN", "").strip()
    if not p1:
        print("Preencha GLOBO_HCAPTCHA_TOKEN no .env antes de executar.")
        return 1

    environment = os.environ.copy()
    environment["GLOBO_P1"] = p1

    for filename, label in STEPS:
        run_step(filename, label, environment)
        if args.stop_after == filename.removesuffix(".py"):
            print(f"\nFluxo parado após {filename}.")
            return 0

    print("\nFluxo completo concluído com sucesso.")
    print_userinfo()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
