import os
from pathlib import Path
import tempfile
import uuid

import pytest

_test_database_directory = tempfile.TemporaryDirectory()
_previous_database_path = os.environ.get("PESOWISE_DB_PATH")
os.environ["PESOWISE_DB_PATH"] = str(Path(_test_database_directory.name) / "pesowise.db")
import pesowise_web
if _previous_database_path is None:
    os.environ.pop("PESOWISE_DB_PATH", None)
else:
    os.environ["PESOWISE_DB_PATH"] = _previous_database_path

from pesowise_web import app, get_db


def make_email(prefix):
    return f"{prefix}{uuid.uuid4().hex[:8]}@gmail.com"


@pytest.fixture
def sent_verification_codes(monkeypatch):
    codes = {}
    monkeypatch.setattr(
        pesowise_web,
        "send_verification_email",
        lambda email, code: codes.__setitem__(email, code),
    )
    return codes


@pytest.fixture
def sent_password_reset_codes(monkeypatch):
    codes = {}
    monkeypatch.setattr(
        pesowise_web,
        "send_password_reset_email",
        lambda email, code: codes.__setitem__(email, code),
    )
    return codes


@pytest.fixture(autouse=True)
def temporary_database(monkeypatch, tmp_path):
    monkeypatch.setattr(pesowise_web, "DB_PATH", tmp_path / "test.db")
    pesowise_web.init_db()


def verify_registration(client, email, codes):
    return client.post(
        "/api/verify-email",
        json={"email": email, "code": codes[email]},
    )


def test_register_login_and_invalid_account_rejected(sent_verification_codes):
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
        assert register.status_code == 202, register.get_data(as_text=True)
        assert client.post(
            '/api/login',
            json={'email': email, 'password': 'StrongPass123!'}
        ).status_code == 401
        wrong_code = client.post(
            '/api/verify-email',
            json={
                'email': email,
                'code': '000000' if sent_verification_codes[email] != '000000' else '000001',
            },
        )
        assert wrong_code.status_code == 400
        verified = verify_registration(client, email, sent_verification_codes)
        assert verified.status_code == 201, verified.get_data(as_text=True)

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


def test_registration_rejects_non_gmail_addresses(sent_verification_codes):
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    with app.test_client() as client:
        response = client.post(
            '/api/register',
            json={
                'name': 'Ana Cruz',
                'email': 'ana@example.com',
                'password': 'StrongPass123!',
                'confirmPassword': 'StrongPass123!',
                'allowance': 350,
            },
        )
        assert response.status_code == 400
        assert sent_verification_codes == {}


def test_password_reset_uses_email_code_and_password_change_requires_current_password(
    sent_verification_codes,
    sent_password_reset_codes,
):
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    with app.test_client() as client:
        reset_email = make_email('reset')
        register = client.post(
            '/api/register',
            json={
                'name': 'Reset User',
                'email': reset_email,
                'password': 'OldPass123!',
                'confirmPassword': 'OldPass123!',
                'allowance': 300,
            },
        )
        assert register.status_code == 202
        assert verify_registration(client, reset_email, sent_verification_codes).status_code == 201

        unknown_reset_email = make_email('unknownreset')
        unknown_email_reset = client.post(
            '/api/request-password-reset',
            json={'email': unknown_reset_email},
        )
        request_code = client.post(
            '/api/request-password-reset',
            json={'email': reset_email},
        )
        assert request_code.status_code == 202
        assert unknown_email_reset.status_code == request_code.status_code
        assert unknown_email_reset.get_json() == request_code.get_json()
        assert set(sent_password_reset_codes) == {reset_email}

        missing_code = client.post(
            '/api/reset-password',
            json={
                'email': reset_email,
                'newPassword': 'NewPass456!',
                'confirmPassword': 'NewPass456!',
            },
        )
        assert missing_code.status_code == 400
        wrong_code = client.post(
            '/api/reset-password',
            json={
                'email': reset_email,
                'code': '000000' if sent_password_reset_codes[reset_email] != '000000' else '000001',
                'newPassword': 'NewPass456!',
                'confirmPassword': 'NewPass456!',
            },
        )
        assert wrong_code.status_code == 400
        unknown_reset = client.post(
            '/api/reset-password',
            json={
                'email': unknown_reset_email,
                'code': '123456',
                'newPassword': 'NewPass456!',
                'confirmPassword': 'NewPass456!',
            },
        )
        assert unknown_reset.status_code == wrong_code.status_code
        assert unknown_reset.get_json() == wrong_code.get_json()

        reset_ok = client.post(
            '/api/reset-password',
            json={
                'email': reset_email,
                'code': sent_password_reset_codes[reset_email],
                'newPassword': 'NewPass456!',
                'confirmPassword': 'NewPass456!',
            },
        )
        assert reset_ok.status_code == 200, reset_ok.get_data(as_text=True)
        assert client.get('/api/me').status_code == 401

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

        missing_current_password = client.post(
            '/api/change-password',
            json={
                'newPassword': 'NextPass789!',
                'confirmPassword': 'NextPass789!',
            },
        )
        assert missing_current_password.status_code == 400
        wrong_current_password = client.post(
            '/api/change-password',
            json={
                'currentPassword': 'WrongPass999!',
                'newPassword': 'NextPass789!',
                'confirmPassword': 'NextPass789!',
            },
        )
        assert wrong_current_password.status_code == 401
        password_change = client.post(
            '/api/change-password',
            json={
                'currentPassword': 'NewPass456!',
                'newPassword': 'NextPass789!',
                'confirmPassword': 'NextPass789!',
            },
        )
        assert password_change.status_code == 200


def test_password_reset_code_expires_and_locks_after_too_many_attempts(
    sent_verification_codes,
    sent_password_reset_codes,
):
    app.config['TESTING'] = True

    with app.test_client() as client:
        email = make_email('expiredreset')
        register = client.post(
            '/api/register',
            json={
                'name': 'Reset User',
                'email': email,
                'password': 'OldPass123!',
                'confirmPassword': 'OldPass123!',
                'allowance': 300,
            },
        )
        assert register.status_code == 202
        assert verify_registration(client, email, sent_verification_codes).status_code == 201
        assert client.post('/api/request-password-reset', json={'email': email}).status_code == 202

        with get_db() as db:
            db.execute(
                'UPDATE password_reset_verifications SET expires_at = 0 WHERE email = ?',
                (email,),
            )
        expired = client.post(
            '/api/reset-password',
            json={
                'email': email,
                'code': sent_password_reset_codes[email],
                'newPassword': 'NewPass456!',
                'confirmPassword': 'NewPass456!',
            },
        )
        assert expired.status_code == 400

        assert client.post('/api/request-password-reset', json={'email': email}).status_code == 202
        wrong_reset_code = '000000' if sent_password_reset_codes[email] != '000000' else '000001'
        for _ in range(pesowise_web.MAX_VERIFICATION_ATTEMPTS - 1):
            incorrect = client.post(
                '/api/reset-password',
                json={
                    'email': email,
                    'code': wrong_reset_code,
                    'newPassword': 'NewPass456!',
                    'confirmPassword': 'NewPass456!',
                },
            )
            assert incorrect.status_code == 400
        locked = client.post(
            '/api/reset-password',
            json={
                'email': email,
                'code': wrong_reset_code,
                'newPassword': 'NewPass456!',
                'confirmPassword': 'NewPass456!',
            },
        )
        assert locked.status_code == 400
        assert locked.get_json() == expired.get_json()
        invalidated_code = client.post(
            '/api/reset-password',
            json={
                'email': email,
                'code': sent_password_reset_codes[email],
                'newPassword': 'NewPass456!',
                'confirmPassword': 'NewPass456!',
            },
        )
        assert invalidated_code.status_code == 400
        assert invalidated_code.get_json() == locked.get_json()


def test_user_budget_data_persists_server_side_for_multi_device_access(sent_verification_codes):
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
        assert register.status_code == 202, register.get_data(as_text=True)
        verified = verify_registration(client_one, email, sent_verification_codes)
        assert verified.status_code == 201, verified.get_data(as_text=True)

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


def test_account_deletion_requires_current_password_and_removes_user_data(sent_verification_codes):
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
        assert register.status_code == 202
        verified = verify_registration(client, email, sent_verification_codes)
        assert verified.status_code == 201
        user_id = verified.get_json()['user']['id']

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


def test_savings_goals_require_valid_deadline_and_allow_deadline_updates(sent_verification_codes):
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
        assert register.status_code == 202
        verified = verify_registration(client, email, sent_verification_codes)
        assert verified.status_code == 201

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


def test_savings_goal_accepts_a_custom_contribution_amount(sent_verification_codes):
    app.config['TESTING'] = True

    with app.test_client() as client:
        email = make_email('customsaving')
        register = client.post(
            '/api/register',
            json={
                'name': 'Savings User',
                'email': email,
                'password': 'StrongPass123!',
                'confirmPassword': 'StrongPass123!',
                'allowance': 300,
            },
        )
        assert register.status_code == 202
        verified = verify_registration(client, email, sent_verification_codes)
        assert verified.status_code == 201

        created = client.post(
            '/api/goals',
            json={
                'name': 'Emergency Fund',
                'target': 250,
                'saved': 100,
                'deadline': '2030-01-01',
            },
        )
        assert created.status_code == 201
        goal_id = created.get_json()['goal']['id']

        contribution = client.post(
            f'/api/goals/{goal_id}/contribute',
            json={'amount': 37.5},
        )
        assert contribution.status_code == 200
        assert contribution.get_json()['goal']['saved'] == 137.5

        invalid_contribution = client.post(
            f'/api/goals/{goal_id}/contribute',
            json={'amount': 0},
        )
        assert invalid_contribution.status_code == 400
