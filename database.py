import psycopg2
import os
from typing import Optional
from dotenv import load_dotenv

# Carregar variáveis de ambiente do arquivo .env
load_dotenv()

# Configurações do PostgreSQL
POSTGRES_CONFIG = {
    'host': os.getenv('POSTGRES_HOST'),
    'port': int(os.getenv('POSTGRES_PORT', '5432')),
    'user': os.getenv('POSTGRES_USER'),
    'password': os.getenv('POSTGRES_PASSWORD'),
    'database': os.getenv('POSTGRES_DB')
}

def get_db_connection():
    """Conecta ao banco de dados PostgreSQL"""
    try:
        conn = psycopg2.connect(**POSTGRES_CONFIG)
        conn.autocommit = False
        return conn
    except psycopg2.Error as e:
        print(f"Erro ao conectar ao PostgreSQL: {e}")
        return None

def close_db_connection(conn):
    """Fecha a conexão com o banco de dados"""
    if conn:
        try:
            conn.close()
        except psycopg2.Error as e:
            print(f"Erro ao fechar conexão: {e}")

