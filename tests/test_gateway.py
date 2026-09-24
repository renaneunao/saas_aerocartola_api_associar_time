import globo_login_server as gateway


def test_pkce_context_is_self_consistent():
    context = gateway._new_pkce_context()

    assert gateway.CLIENT_ID == 'cartola-web@apps.globoid'
    assert gateway.SERVICE_ID == 6860
    assert gateway.REDIRECT_URI == 'https://cartola.globo.com'
    assert context.state
    assert context.nonce
    assert context.code_verifier
    assert context.code_challenge
    assert context.finish_url.startswith(gateway.OIDC_CONFIRM_URL)
    assert context.state in context.finish_url
    assert context.code_challenge in context.finish_url


def test_health_endpoint_is_available():
    response = gateway.app.test_client().get('/health')

    assert response.status_code == 200
    assert response.get_json() == {'status': 'ok'}


def test_internal_endpoint_rejects_missing_key(monkeypatch):
    monkeypatch.setattr(gateway, 'GATEWAY_SHARED_SECRET', 'local-test-secret')
    response = gateway.app.test_client().post(
        '/internal/v1/teams/authenticate',
        json={
            'user_id': 7,
            'email': 'test@example.com',
            'password': 'password',
            'captcha': 'p1',
        },
    )

    assert response.status_code == 401
    assert response.get_json()['error'] == 'Chamada interna não autorizada.'


def test_internal_association_persists_without_returning_tokens(monkeypatch):
    monkeypatch.setattr(gateway, 'GATEWAY_SHARED_SECRET', 'local-test-secret')
    stored = {}

    def fake_login(email, password, captcha, trace):
        assert email == 'test@example.com'
        assert password == 'password'
        assert captcha == 'p1'
        return (
            {
                'access_token': 'access-secret',
                'refresh_token': 'refresh-secret',
                'id_token': 'id-secret',
            },
            {'globo_id': 'globo-user-1'},
        )

    def fake_team_info(access_token, trace):
        assert access_token == 'access-secret'
        return {'time': {'id': 123, 'nome': 'Time de Teste'}}

    def fake_store_team(**kwargs):
        stored.update(kwargs)
        return 44

    monkeypatch.setattr(gateway, '_login_and_get_auth_result', fake_login)
    monkeypatch.setattr(gateway, '_cartola_team_info', fake_team_info)
    monkeypatch.setattr(gateway, '_store_team', fake_store_team)

    response = gateway.app.test_client().post(
        '/internal/v1/teams/authenticate',
        headers={'X-Gateway-Key': 'local-test-secret'},
        json={
            'user_id': 9,
            'email': 'test@example.com',
            'password': 'password',
            'captcha': 'p1',
        },
    )

    body = response.get_json()
    assert response.status_code == 200
    assert body['ok'] is True
    assert body['team_id'] == 44
    assert body['team_name'] == 'Time de Teste'
    assert body['cartola_team_id'] == 123
    assert 'access-secret' not in response.get_data(as_text=True)
    assert 'refresh-secret' not in response.get_data(as_text=True)
    assert stored == {
        'user_id': 9,
        'access_token': 'access-secret',
        'refresh_token': 'refresh-secret',
        'id_token': 'id-secret',
        'team_name': 'Time de Teste',
    }


def test_localhost_aliases_are_allowed_by_cors(monkeypatch):
    monkeypatch.setattr(
        gateway,
        'SITE_ORIGINS',
        {'http://localhost:9000', 'http://127.0.0.1:9000'},
    )
    response = gateway.app.test_client().get(
        '/health',
        headers={'Origin': 'http://127.0.0.1:9000'},
    )

    assert response.status_code == 200
    assert response.headers['Access-Control-Allow-Origin'] == 'http://127.0.0.1:9000'


def test_internal_association_requires_cartola_team_name(monkeypatch):
    monkeypatch.setattr(gateway, 'GATEWAY_SHARED_SECRET', 'local-test-secret')

    monkeypatch.setattr(
        gateway,
        '_login_and_get_auth_result',
        lambda *args: (
            {
                'access_token': 'access-secret',
                'refresh_token': 'refresh-secret',
                'id_token': 'id-secret',
            },
            {},
        ),
    )
    monkeypatch.setattr(gateway, '_cartola_team_info', lambda *args: {'time': {}})
    store_called = False

    def fail_if_stored(**kwargs):
        nonlocal store_called
        store_called = True

    monkeypatch.setattr(gateway, '_store_team', fail_if_stored)
    response = gateway.app.test_client().post(
        '/internal/v1/teams/authenticate',
        headers={'X-Gateway-Key': 'local-test-secret'},
        json={
            'user_id': 9,
            'email': 'test@example.com',
            'password': 'password',
            'captcha': 'p1',
        },
    )

    assert response.status_code == 401
    assert 'nome do time Cartola' in response.get_json()['error']
    assert store_called is False


def test_internal_association_rejects_duplicate_team(monkeypatch):
    monkeypatch.setattr(gateway, 'GATEWAY_SHARED_SECRET', 'local-test-secret')
    monkeypatch.setattr(
        gateway,
        '_login_and_get_auth_result',
        lambda *args: (
            {
                'access_token': 'access-secret',
                'refresh_token': 'refresh-secret',
                'id_token': 'id-secret',
            },
            {},
        ),
    )
    monkeypatch.setattr(
        gateway,
        '_cartola_team_info',
        lambda *args: {'time': {'id': 321, 'nome': 'Time Repetido'}},
    )
    monkeypatch.setattr(
        gateway,
        '_store_team',
        lambda **kwargs: (_ for _ in ()).throw(
            gateway.DuplicateTeamError('Este time já está associado à sua conta.')
        ),
    )

    response = gateway.app.test_client().post(
        '/internal/v1/teams/authenticate',
        headers={'X-Gateway-Key': 'local-test-secret'},
        json={
            'user_id': 9,
            'email': 'test@example.com',
            'password': 'password',
            'captcha': 'p1',
        },
    )

    assert response.status_code == 409
    assert response.get_json()['code'] == 'duplicate_team'
