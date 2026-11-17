import uuid

from pesowise_web import app, get_db


def make_email(prefix):
    return f"{prefix}{uuid.uuid4().hex[:8]}@lspu.edu.ph"


def test_register_login_and_invalid_account_rejected():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    with app.test_client() as client:
        email = make_email('ana')
        register = client.post(
            '/api/register',
            json={
                'name': 'Ana Cruz',
                'email': email,
                'password': 'StrongPass123!',
                'confirmPassword': 'StrongPass123!',
                'allowance': 350
            }
        )
        assert register.status_code == 201, register.get_data(as_text=True)

        duplicate = client.post(
            '/api/register',
            json={
                'name': 'Ana Cruz',
                'email': email,
                'password': 'OtherPass123!',
                'confirmPassword': 'OtherPass123!',
                'allowance': 400
            }
        )
        assert duplicate.status_code == 409

        invalid_login = client.post(
            '/api/login',
            json={'email': 'ghost@lspu.edu.ph', 'password': 'WrongPass123!'}
        )
        assert invalid_login.status_code == 401

        valid_login = client.post(
            '/api/login',
            json={'email': email, 'password': 'StrongPass123!'}
        )
        assert valid_login.status_code == 200, valid_login.get_data(as_text=True)
        payload = valid_login.get_json()
        assert payload['user']['email'] == email
        assert payload['user']['name'] == 'Ana Cruz'


def test_password_change_requires_current_password_verification():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    with app.test_client() as client:
        reset_email = make_email('reset')
        client.post(
            '/api/register',
            json={
                'name': 'Reset User',
                'email': reset_email,
                'password': 'OldPass123!',
                'confirmPassword': 'OldPass123!',
                'allowance': 300,
            },
        )

        mismatch = client.post(
            '/api/register',
            json={
                'name': 'Other User',
                'email': make_email('otherreset'),
                'password': 'Alpha123!',
                'confirmPassword': 'Beta123!',
                'allowance': 300,
            },
        )
        assert mismatch.status_code == 400

        reset_without_current_password = client.post(
            '/api/reset-password',
            json={
                'email': reset_email,
                'newPassword': 'NewPass456!',
                'confirmPassword': 'NewPass456!',
            },
        )
        assert reset_without_current_password.status_code == 400

        wrong_current_password = client.post(
            '/api/reset-password',
            json={
                'email': reset_email,
                'currentPassword': 'WrongPass999!',
                'newPassword': 'NewPass456!',
                'confirmPassword': 'NewPass456!',
            },
        )
        assert wrong_current_password.status_code == 401

        reset_ok = client.post(
            '/api/reset-password',
            json={
                'email': reset_email,
                'currentPassword': 'OldPass123!',
                'newPassword': 'NewPass456!',
                'confirmPassword': 'NewPass456!',
            },
        )
        assert reset_ok.status_code == 200, reset_ok.get_data(as_text=True)

        bad_login = client.post(
            '/api/login',
            json={'email': reset_email, 'password': 'OldPass123!'}
        )
        assert bad_login.status_code == 401

        good_login = client.post(
            '/api/login',
            json={'email': reset_email, 'password': 'NewPass456!'}
        )
        assert good_login.status_code == 200


def test_user_budget_data_persists_server_side_for_multi_device_access():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    email = make_email('persist')

    with app.test_client() as client_one:
        register = client_one.post(
            '/api/register',
            json={
                'name': 'Persist User',
                'email': email,
                'password': 'StrongPass123!',
                'confirmPassword': 'StrongPass123!',
                'allowance': 500,
            },
        )
        assert register.status_code == 201, register.get_data(as_text=True)

        expense = client_one.post(
            '/api/expenses',
            json={
                'description': 'Jeepney fare',
                'amount': 45.00,
                'category': 'Transportation',
                'date': '2026-11-14'
            },
        )
        assert expense.status_code == 201, expense.get_data(as_text=True)

        goal = client_one.post(
            '/api/goals',
            json={
                'name': 'Textbook',
                'target': 1200,
                'saved': 300,
                'deadline': '2026-12-01',
            },
        )
        assert goal.status_code == 201, goal.get_data(as_text=True)

        dashboard = client_one.get('/api/dashboard')
        assert dashboard.status_code == 200, dashboard.get_data(as_text=True)
        payload = dashboard.get_json()
        assert payload['allowance'] == 500
        assert any(item['description'] == 'Jeepney fare' for item in payload['expenses'])
        assert any(item['name'] == 'Textbook' for item in payload['goals'])
        assert next(item for item in payload['goals'] if item['name'] == 'Textbook')['deadline'] == '2026-12-01'

    with app.test_client() as client_two:
        login = client_two.post(
            '/api/login',
            json={'email': email, 'password': 'StrongPass123!'}
        )
        assert login.status_code == 200, login.get_data(as_text=True)

        dashboard = client_two.get('/api/dashboard')
        assert dashboard.status_code == 200, dashboard.get_data(as_text=True)
        payload = dashboard.get_json()
        assert payload['allowance'] == 500
        assert any(item['description'] == 'Jeepney fare' for item in payload['expenses'])
        assert any(item['name'] == 'Textbook' for item in payload['goals'])


def test_account_deletion_requires_current_password_and_removes_user_data():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    with app.test_client() as client:
        unauthenticated_delete = client.delete(
            '/api/account',
            json={'currentPassword': 'StrongPass123!'},
        )
        assert unauthenticated_delete.status_code == 401

        email = make_email('delete')
        register = client.post(
            '/api/register',
            json={
                'name': 'Delete User',
                'email': email,
                'password': 'StrongPass123!',
                'confirmPassword': 'StrongPass123!',
                'allowance': 300,
            },
        )
        assert register.status_code == 201
        user_id = register.get_json()['user']['id']

        missing_password = client.delete('/api/account', json={})
        assert missing_password.status_code == 400
        malformed_payload = client.delete('/api/account', json=['not-a-password'])
        assert malformed_payload.status_code == 400

        expense = client.post(
            '/api/expenses',
            json={
                'description': 'Lunch',
                'amount': 50,
                'category': 'Food',
                'date': '2026-11-17',
            },
        )
        assert expense.status_code == 201
        goal = client.post(
            '/api/goals',
            json={'name': 'Books', 'target': 1000, 'saved': 100, 'deadline': '2026-11-20'},
        )
        assert goal.status_code == 201

        incorrect_password = client.delete(
            '/api/account',
            json={'currentPassword': 'WrongPass123!'},
        )
        assert incorrect_password.status_code == 401
        dashboard = client.get('/api/dashboard')
        assert dashboard.status_code == 200
        assert len(dashboard.get_json()['expenses']) == 1
        assert len(dashboard.get_json()['goals']) == 1

        deleted = client.delete(
            '/api/account',
            json={'currentPassword': 'StrongPass123!'},
        )
        assert deleted.status_code == 200
        assert client.get('/api/me').status_code == 401
        assert client.post(
            '/api/login',
            json={'email': email, 'password': 'StrongPass123!'},
        ).status_code == 401

    with get_db() as db:
        assert db.execute('SELECT id FROM users WHERE id = ?', (user_id,)).fetchone() is None
        assert db.execute('SELECT id FROM expenses WHERE user_id = ?', (user_id,)).fetchone() is None
        assert db.execute('SELECT id FROM savings_goals WHERE user_id = ?', (user_id,)).fetchone() is None


def test_savings_goals_require_valid_deadline_and_allow_deadline_updates():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    with app.test_client() as client:
        email = make_email('deadline')
        register = client.post(
            '/api/register',
            json={
                'name': 'Deadline User',
                'email': email,
                'password': 'StrongPass123!',
                'confirmPassword': 'StrongPass123!',
                'allowance': 300,
            },
        )
        assert register.status_code == 201

        missing_deadline = client.post(
            '/api/goals',
            json={'name': 'Books', 'target': 1000, 'saved': 100},
        )
        assert missing_deadline.status_code == 400
        invalid_deadline = client.post(
            '/api/goals',
            json={'name': 'Books', 'target': 1000, 'saved': 100, 'deadline': '2026-02-30'},
        )
        assert invalid_deadline.status_code == 400

        created = client.post(
            '/api/goals',
            json={
                'name': 'Books',
                'target': 1000,
                'saved': 100,
                'deadline': '2030-01-01',
            },
        )
        assert created.status_code == 201
        goal_id = created.get_json()['goal']['id']
        assert created.get_json()['goal']['deadline'] == '2030-01-01'

        updated = client.put(
            f'/api/goals/{goal_id}',
            json={
                'name': 'Books',
                'target': 1000,
                'saved': 100,
                'deadline': '2030-02-01',
            },
        )
        assert updated.status_code == 200
        assert updated.get_json()['goal']['deadline'] == '2030-02-01'
