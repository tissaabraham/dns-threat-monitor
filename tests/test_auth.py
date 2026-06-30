# Tests for user account creation, password hashing, verification, and profile updates.

import os
import sys
import sqlite3
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from database.database import DatabaseManager


class TestUserAuth:
    """Test the user authentication methods on the database manager."""

    def setup_method(self):
        """Create a temporary database for each test."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()

        original_db_file = DatabaseManager.DB_FILE
        DatabaseManager.DB_FILE = self.temp_db.name
        self.db = DatabaseManager()
        DatabaseManager.DB_FILE = original_db_file

    def teardown_method(self):
        """Close and remove the temporary database."""
        if self.db:
            self.db.close()
        try:
            os.unlink(self.temp_db.name)
        except OSError:
            pass

    def test_users_table_exists(self):
        cursor = self.db.connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        assert cursor.fetchone() is not None

    def test_create_user_hashes_password(self):
        user_id = self.db.create_user("alice", "secret123", "Alice A", "alice@example.com")
        assert user_id > 0
        user = self.db.get_user_by_username("alice")
        assert user is not None
        # The stored value must not be the plaintext password.
        assert user['password_hash'] != "secret123"

    def test_verify_user_correct_password(self):
        self.db.create_user("bob", "password1")
        user = self.db.verify_user("bob", "password1")
        assert user is not None
        assert user['username'] == "bob"

    def test_verify_user_wrong_password(self):
        self.db.create_user("carol", "password1")
        assert self.db.verify_user("carol", "wrongpass") is None

    def test_verify_user_unknown_username(self):
        assert self.db.verify_user("nobody", "password1") is None

    def test_duplicate_username_rejected(self):
        self.db.create_user("dave", "password1")
        with pytest.raises(sqlite3.IntegrityError):
            self.db.create_user("dave", "password2")

    def test_update_password_requires_current(self):
        user_id = self.db.create_user("erin", "oldpassword")
        assert self.db.update_password(user_id, "wrong", "newpassword") is False
        assert self.db.update_password(user_id, "oldpassword", "newpassword") is True
        assert self.db.verify_user("erin", "newpassword") is not None

    def test_update_profile(self):
        user_id = self.db.create_user("frank", "password1")
        assert self.db.update_profile(user_id, "Frank F", "frank@example.com") is True
        user = self.db.get_user_by_id(user_id)
        assert user['full_name'] == "Frank F"
        assert user['email'] == "frank@example.com"

    def test_count_users(self):
        assert self.db.count_users() == 0
        self.db.create_user("gina", "password1")
        assert self.db.count_users() == 1


class TestLoginEndpoint:
    """Test the /login HTTP endpoint using the Flask test client."""

    def setup_method(self):
        """Create a temp database, seed a user, and wire up the Flask test client."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()

        import dashboard.app as app_module

        original_db_file = DatabaseManager.DB_FILE
        DatabaseManager.DB_FILE = self.temp_db.name
        self.db = DatabaseManager()
        DatabaseManager.DB_FILE = original_db_file

        # Point the running app at the temp database.
        app_module.db = self.db
        self.db.create_user("testuser", "testpassword1")

        app_module.app.config['TESTING'] = True
        # Disable rate limiting so individual tests are not affected by each other.
        app_module.app.config['RATELIMIT_ENABLED'] = False
        self.app = app_module.app.test_client()
        self.app_module = app_module

    def teardown_method(self):
        """Restore the app state and remove the temp database."""
        self.db.close()
        try:
            os.unlink(self.temp_db.name)
        except OSError:
            pass

    def _post_login(self, username, password):
        return self.app.post(
            '/login',
            json={'username': username, 'password': password}
        )

    def test_login_correct_credentials(self):
        res = self._post_login('testuser', 'testpassword1')
        assert res.status_code == 200
        assert res.get_json()['ok'] is True

    def test_login_wrong_password(self):
        res = self._post_login('testuser', 'wrongpassword')
        assert res.status_code == 401
        assert 'error' in res.get_json()

    def test_login_unknown_user(self):
        res = self._post_login('nobody', 'testpassword1')
        assert res.status_code == 401
        assert 'error' in res.get_json()

    def test_login_rate_limit(self):
        # Re-enable rate limiting just for this test.
        self.app_module.app.config['RATELIMIT_ENABLED'] = True
        # Send 10 requests — all should be processed (pass or fail on credentials).
        for _ in range(10):
            self._post_login('testuser', 'wrongpassword')
        # The 11th request must be blocked with 429.
        res = self._post_login('testuser', 'wrongpassword')
        assert res.status_code == 429
        data = res.get_json()
        assert 'error' in data
        self.app_module.app.config['RATELIMIT_ENABLED'] = False
