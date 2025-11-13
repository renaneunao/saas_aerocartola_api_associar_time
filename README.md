# API Associar Time - Servidor de Recepção de Times

Servidor Flask responsável por receber payloads de times dos usuários via extensão do navegador e associá-los na tabela `acw_teams`.

## Estrutura da Tabela `acw_teams`

A tabela que armazena os times associados aos usuários possui a seguinte estrutura:

| Coluna | Tipo | Nullable | Descrição |
|--------|------|----------|-----------|
| `id` | SERIAL (INTEGER) | NOT NULL | Chave primária auto-incrementável |
| `user_id` | INTEGER | NOT NULL | ID do usuário (FK para acw_users.id) |
| `access_token` | TEXT | NOT NULL | Token de acesso do Cartola |
| `refresh_token` | TEXT | NOT NULL | Token de refresh do Cartola (contém IDs dos times) |
| `id_token` | TEXT | NULL | Token de identificação do Cartola (opcional) |
| `team_name` | TEXT | NULL | Nome do time do Cartola (opcional) |
| `created_at` | TIMESTAMP | NOT NULL | Data/hora de criação (default: CURRENT_TIMESTAMP) |
| `updated_at` | TIMESTAMP | NOT NULL | Data/hora de última atualização (default: CURRENT_TIMESTAMP) |

### Relacionamento

```
acw_users (1) ──────< (N) acw_teams
```

- Um usuário pode ter múltiplos times
- Um time pertence a apenas um usuário
- Quando um usuário é deletado, todos os seus times são deletados (CASCADE)

## Endpoint

### POST /api/teams/associate

Associa um time do Cartola a um usuário.

#### Payload Esperado

**Todos os campos são obrigatórios:**
- `user_id` (integer): ID do usuário logado na plataforma
- `refresh_token` (string): Token de refresh do Cartola que contém os IDs dos times
- `access_token` (string): Token de acesso atual do Cartola
- `id_token` (string): Token de identificação do Cartola
- `team_name` (string): Nome do time do Cartola

**Nota:** Se já existir um time com o mesmo `user_id` e `team_name`, os tokens serão atualizados (UPDATE) ao invés de criar um novo registro.

#### Exemplo de Payload

```json
{
    "user_id": 123,
    "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "team_name": "Meu Time FC"
}
```

#### Resposta de Sucesso

**201 - Time criado:**
```json
{
    "success": true,
    "message": "Time criado com sucesso",
    "team": {
        "id": 1,
        "user_id": 123,
        "team_name": "Meu Time FC",
        "created_at": "2024-01-01T12:00:00",
        "updated_at": "2024-01-01T12:00:00"
    }
}
```

**200 - Time atualizado:**
```json
{
    "success": true,
    "message": "Time atualizado com sucesso",
    "team": {
        "id": 1,
        "user_id": 123,
        "team_name": "Meu Time FC",
        "created_at": "2024-01-01T12:00:00",
        "updated_at": "2024-01-01T13:00:00"
    }
}
```

**Nota:** Os tokens não são retornados na resposta por segurança.

#### Respostas de Erro

**400 - Campos obrigatórios faltando:**
```json
{
    "error": "Campos obrigatórios faltando",
    "required": ["user_id", "refresh_token", "access_token", "id_token", "team_name"]
}
```

**404 - Usuário não encontrado:**
```json
{
    "error": "Usuário não encontrado"
}
```

**500 - Erro interno:**
```json
{
    "error": "Erro ao inserir no banco: [detalhes do erro]"
}
```

### GET /health

Endpoint de health check.

**Resposta (200):**
```json
{
    "status": "ok",
    "service": "times-receiver"
}
```

## Configuração

### Variáveis de Ambiente

Crie um arquivo `.env` na raiz do projeto:

```env
# PostgreSQL Configuration
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_USER=postgres
POSTGRES_PASSWORD=sua_senha_aqui
POSTGRES_DB=cartola_manager

# Flask Configuration
FLASK_ENV=production
SECRET_KEY=Ogp3WQ3KTGD2_AcuAk0FFBHZP0erxVip_6aP-W0uk4M

# Server Configuration
FLASK_PORT=5000
```

## Deploy com Docker

### Build da Imagem

A imagem Docker é construída automaticamente pelo GitHub Actions quando há push para a branch `main` ou `master`. A imagem é publicada no Docker Hub como `renaneunao/saas-cartola-times-receiver:latest`.

### Executar o Container

```bash
# Certifique-se de que a rede infra_network existe
docker network create infra_network

# Iniciar o container
docker-compose up -d

# Ver logs
docker-compose logs -f times-receiver
```

### Parar o serviço

```bash
docker-compose down
```

## Logs

Os logs são salvos em `./logs/app.log` e também exibidos no console. Todas as requisições são registradas com:
- Método HTTP e path
- Endereço IP remoto
- Payload (tokens são mascarados por segurança)
- Status da resposta
- Erros e exceções

## Estrutura do Projeto

```
.
├── app.py                 # Aplicação Flask principal
├── database.py            # Módulo de conexão com PostgreSQL
├── requirements.txt       # Dependências Python
├── Dockerfile            # Configuração do container Docker
├── docker-compose.yml    # Orquestração Docker Compose
├── .env                  # Variáveis de ambiente (não versionado)
├── .gitignore           # Arquivos ignorados pelo Git
├── logs/                # Diretório de logs
└── README.md            # Esta documentação
```

## Notas Importantes

- O servidor roda na porta 5001 (mapeada da porta 5000 do container)
- A tabela `acw_teams` deve existir no banco de dados PostgreSQL
- O servidor valida se o `user_id` existe na tabela `acw_users` antes de inserir
- A tabela permite múltiplos times por usuário
- Use a mesma rede Docker (`infra_network`) para comunicação entre containers
- Tokens não são retornados nas respostas por segurança
