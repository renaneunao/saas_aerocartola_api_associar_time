from flask import Flask, request, jsonify
import psycopg2
from database import get_db_connection, close_db_connection
import os
import logging
from dotenv import load_dotenv

# Carregar variáveis de ambiente
load_dotenv()

# Configurar logging
log_dir = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(log_dir, exist_ok=True)

log_file = os.path.join(log_dir, 'app.log')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-me-to-a-secure-random-value-in-production')

# Middleware para logar todas as requisições
@app.before_request
def log_request_info():
    logger.info(f"Request: {request.method} {request.path}")
    logger.info(f"Remote Address: {request.remote_addr}")
    if request.is_json:
        data = request.get_json()
        # Não logar tokens completos por segurança
        safe_data = {}
        if data:
            for key, value in data.items():
                if 'token' in key.lower() and value:
                    safe_data[key] = f"{str(value)[:20]}..." if len(str(value)) > 20 else "***"
                else:
                    safe_data[key] = value
        logger.info(f"Request Body: {safe_data}")

@app.after_request
def log_response_info(response):
    logger.info(f"Response: {response.status_code}")
    return response

@app.route('/api/teams/associate', methods=['POST'])
def associate_team():
    """
    Endpoint para associar um time do Cartola a um usuário.
    Se já existir um time com o mesmo user_id e team_name, faz UPDATE.
    
    Payload esperado:
    {
        "user_id": int,
        "refresh_token": str,
        "access_token": str,
        "id_token": str,
        "team_name": str
    }
    """
    try:
        data = request.get_json()
        logger.info(f"Associating team for user_id: {data.get('user_id') if data else 'N/A'}")
        
        # Validação dos campos obrigatórios
        if not data:
            logger.warning("Empty payload received")
            return jsonify({'error': 'Payload vazio'}), 400
        
        user_id = data.get('user_id')
        refresh_token = data.get('refresh_token')
        access_token = data.get('access_token')
        id_token = data.get('id_token')
        team_name = data.get('team_name')
        
        # Todos os campos são obrigatórios
        if not user_id or not refresh_token or not access_token or not id_token or not team_name:
            logger.warning(f"Missing required fields for user_id: {user_id}")
            return jsonify({
                'error': 'Campos obrigatórios faltando',
                'required': ['user_id', 'refresh_token', 'access_token', 'id_token', 'team_name']
            }), 400
        
        # Validação de tipos
        try:
            user_id = int(user_id)
        except (ValueError, TypeError):
            return jsonify({'error': 'user_id deve ser um número inteiro'}), 400
        
        if not isinstance(refresh_token, str) or len(refresh_token.strip()) == 0:
            return jsonify({'error': 'refresh_token deve ser uma string não vazia'}), 400
        
        if not isinstance(access_token, str) or len(access_token.strip()) == 0:
            return jsonify({'error': 'access_token deve ser uma string não vazia'}), 400
        
        if not isinstance(id_token, str) or len(id_token.strip()) == 0:
            return jsonify({'error': 'id_token deve ser uma string não vazia'}), 400
        
        if not isinstance(team_name, str) or len(team_name.strip()) == 0:
            return jsonify({'error': 'team_name deve ser uma string não vazia'}), 400
        
        # Conectar ao banco
        conn = get_db_connection()
        if not conn:
            logger.error("Failed to connect to database")
            return jsonify({'error': 'Erro ao conectar ao banco de dados'}), 500
        
        try:
            # Verificar se o usuário existe
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM acw_users WHERE id = %s', (user_id,))
            if not cursor.fetchone():
                cursor.close()
                close_db_connection(conn)
                logger.warning(f"User not found: user_id={user_id}")
                return jsonify({'error': 'Usuário não encontrado'}), 404
            
            # Verificar se já existe um time com o mesmo user_id e team_name
            cursor.execute('''
                SELECT id, created_at FROM acw_teams 
                WHERE user_id = %s AND team_name = %s
            ''', (user_id, team_name))
            
            existing_team = cursor.fetchone()
            
            if existing_team:
                # UPDATE: Time já existe, atualizar os tokens
                team_id = existing_team[0]
                created_at = existing_team[1]
                
                cursor.execute('''
                    UPDATE acw_teams 
                    SET access_token = %s,
                        refresh_token = %s,
                        id_token = %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                    RETURNING user_id, team_name, updated_at
                ''', (access_token, refresh_token, id_token, team_id))
                
                result = cursor.fetchone()
                returned_user_id = result[0]
                returned_team_name = result[1]
                updated_at = result[2]
                
                conn.commit()
                logger.info(f"Team updated: team_id={team_id}, user_id={returned_user_id}, team_name={returned_team_name}")
                action = 'atualizado'
            else:
                # INSERT: Novo time
                cursor.execute('''
                    INSERT INTO acw_teams (user_id, access_token, refresh_token, id_token, team_name)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id, user_id, team_name, created_at, updated_at
                ''', (user_id, access_token, refresh_token, id_token, team_name))
                
                result = cursor.fetchone()
                team_id = result[0]
                returned_user_id = result[1]
                returned_team_name = result[2]
                created_at = result[3]
                updated_at = result[4]
                
                conn.commit()
                logger.info(f"Team created: team_id={team_id}, user_id={returned_user_id}, team_name={returned_team_name}")
                action = 'criado'
            
            # Montar resposta com todos os campos relevantes
            # Nota: Tokens não são retornados por segurança (são dados sensíveis)
            response_data = {
                'success': True,
                'message': f'Time {action} com sucesso',
                'team': {
                    'id': team_id,
                    'user_id': returned_user_id,
                    'team_name': returned_team_name,
                    'created_at': created_at.isoformat() if created_at else None,
                    'updated_at': updated_at.isoformat() if updated_at else None
                }
            }
            
            status_code = 200 if action == 'atualizado' else 201
            return jsonify(response_data), status_code
            
        except psycopg2.IntegrityError as e:
            conn.rollback()
            logger.error(f"Integrity error: {str(e)}")
            return jsonify({'error': 'Erro de integridade: possivelmente usuário não existe'}), 400
        except psycopg2.Error as e:
            conn.rollback()
            logger.error(f"Database error: {str(e)}")
            return jsonify({'error': f'Erro ao inserir no banco: {str(e)}'}), 500
        finally:
            cursor.close()
            close_db_connection(conn)
            
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        return jsonify({'error': f'Erro interno: {str(e)}'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Endpoint de health check"""
    logger.info("Health check requested")
    return jsonify({'status': 'ok', 'service': 'times-receiver'}), 200

if __name__ == '__main__':
    port = int(os.getenv('FLASK_PORT', '5000'))
    logger.info(f"Starting Flask application on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)

