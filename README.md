# hCaptcha Study Lab

Projeto local de estudo sobre a integração de um widget hCaptcha oficial com um fluxo HTTP de autenticação OIDC/PKCE.

O estudo não gera, resolve ou contorna desafios. O P1 é produzido pelo widget oficial após a interação humana e enviado uma única vez ao fluxo de autenticação.

## Componentes

- `globo_login_server.py`: backend Flask local; executa o fluxo completo em uma única chamada.
- `frontend/`: demo React com o widget oficial do hCaptcha.
- `globo_flow/scripts/`: scripts numerados para inspeção e execução isolada:
  `00_context`, `03_authenticate`, `04_oidc_callback`, `05_token` e `06_userinfo`.
- `globo_flow/json/`: saída local ignorada pelo Git; pode conter dados sensíveis.

## Fluxo

```text
00_context → 03_authenticate → 04_oidc_callback → 05_token → 06_userinfo
```

O backend local reproduz a mesma sequência: bootstrap sem P1, redirect OIDC real, `save-redirect-url`, autenticação com P1, provisionamento/finish/confirm, troca do code por tokens e consulta de userinfo.

## Execução local

1. Copie `.env.example` para `.env` e preencha apenas em ambiente local.
2. Instale as dependências Python:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

3. Inicie o backend:

   ```powershell
   python globo_login_server.py
   ```

4. Em outro terminal, instale e inicie o demo:

   ```powershell
   cd frontend
   npm install
   npm start
   ```

Abra `http://localhost:9000/`, preencha as credenciais, marque o captcha e execute o fluxo completo.

## Gateway interno do Aero Cartola

Além do endpoint de laboratório `/api/globo-login`, o backend expõe
`POST /internal/v1/teams/authenticate`. Ele é destinado exclusivamente ao
web app, protegido pelo header `X-Gateway-Key` e pela variável
`GATEWAY_SHARED_SECRET`.

O payload interno contém `user_id`, email, senha, P1 do hCaptcha e nome
opcional do time. O gateway conclui o fluxo, usa o access token para buscar
os metadados do time e insere os tokens diretamente na tabela existente
`acw_teams`. Nenhum token é devolvido na resposta e o gateway não cria nem
recria tabelas.

O `docker-compose.yml` conecta o serviço à rede externa `infra_network` sem
publicar a porta para fora da rede Docker. O web app deve usar o alias
`cartola-aero-associar-gateway:5001` e compartilhar apenas o segredo interno.

## Segurança

Nunca versione `.env`, P1, senhas, cookies, authorization codes, tokens, `userinfo.json` ou outros resultados de execução. O backend e o demo são destinados a uso local e autorizado.
