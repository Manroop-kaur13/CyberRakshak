import os
import unittest
from contextlib import contextmanager
import uuid
from pathlib import Path

import server


class DemoLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_db = server.DB
        cls.original_url = server.DATABASE_URL
        cls.test_db_dir = Path(server.ROOT) / '.test-runtime'
        cls.test_db_dir.mkdir(exist_ok=True)
        server.DATABASE_URL = ''

    @classmethod
    def tearDownClass(cls):
        server.DB = cls.original_db
        server.DATABASE_URL = cls.original_url
        for path in cls.test_db_dir.glob('*'):
            path.unlink(missing_ok=True)
        cls.test_db_dir.rmdir()

    @contextmanager
    def db(self):
        c = server.connect()
        try:
            yield c
            c.commit()
        finally:
            c.close()

    def setUp(self):
        server.DB = self.test_db_dir / f'{uuid.uuid4().hex}.sqlite3'
        server.DEMO_ADMIN_PASSWORD = 'test-only-password-that-is-long-enough'
        server.DEMO_SESSION_SECRET = b'test-only-session-secret-32-bytes-minimum'
        server.migrate()
        server.seed()
        self.admin = {'admin_name': 'Presenter'}
        self.session_id = 'session-' + uuid.uuid4().hex
        now = server._now()
        expiry = (server.datetime.now(server.timezone.utc) + server.timedelta(hours=1)).isoformat(timespec='seconds')
        with self.db() as c:
            server._db(c, 'INSERT INTO demo_sessions(id,created_by,created_at,expires_at,status) VALUES (?,?,?,?,?)',
                       (self.session_id, 'Presenter', now, expiry, 'ACTIVE'))

    def tearDown(self):
        server.DB.unlink(missing_ok=True)

    def request(self, name='Jordan Sample', key=None):
        return server._create_demo_request(self.session_id, name, key or str(uuid.uuid4()), 'test-client')

    def test_create_persists_and_shows_in_presenter_queue(self):
        code, req = self.request()
        self.assertEqual(code, 201)
        with self.db() as c:
            row = server._db(c, 'SELECT * FROM demo_login_requests WHERE id=?', (req['id'],)).fetchone()
            queue = server._db(c, 'SELECT * FROM demo_login_requests WHERE session_id=? AND status=?', (self.session_id, 'PENDING')).fetchall()
        self.assertEqual(row['display_name'], 'Jordan Sample')
        self.assertEqual(len(queue), 1)
        self.assertTrue(req['expires_at'])

    def test_idempotent_retry_returns_original_request(self):
        key = str(uuid.uuid4())
        _, first = self.request(key=key)
        code, retry = self.request(key=key)
        self.assertEqual(code, 200)
        self.assertEqual(first['id'], retry['id'])
        with self.db() as c:
            count = server._db(c, 'SELECT COUNT(*) AS n FROM demo_login_requests WHERE session_id=?', (self.session_id,)).fetchone()['n']
        self.assertEqual(count, 1)

    def test_approve_and_decline_are_persisted_and_audited(self):
        _, approved = self.request()
        result, decided = server._decide_demo_request(approved['id'], 'APPROVED', self.admin)
        self.assertEqual(result, 200)
        self.assertEqual(decided['status'], 'APPROVED')
        with self.db() as c:
            row = server._db(c, 'SELECT status,decided_by,decided_at FROM demo_login_requests WHERE id=?', (approved['id'],)).fetchone()
            audit = [server.json.loads(r['body']) for r in server._db(c, "SELECT body FROM records WHERE kind='audit'", ()).fetchall()]
        self.assertEqual(row['decided_by'], 'Presenter')
        self.assertTrue(row['decided_at'])
        self.assertTrue(any(x['entityId'] == approved['id'] and 'approve' in x['action'] for x in audit))
        _, declined = self.request()
        code, result = server._decide_demo_request(declined['id'], 'DECLINED', self.admin)
        self.assertEqual(code, 200)
        self.assertEqual(result['status'], 'DECLINED')
        code, _ = server._decide_demo_request(declined['id'], 'APPROVED', self.admin)
        self.assertEqual(code, 409)

    def test_expired_request_is_terminal(self):
        _, req = self.request()
        past = (server.datetime.now(server.timezone.utc) - server.timedelta(seconds=5)).isoformat(timespec='seconds')
        with self.db() as c:
            server._db(c, 'UPDATE demo_login_requests SET expires_at=? WHERE id=?', (past, req['id']))
        result = server._expire_request_by_id(req['id'])
        self.assertEqual(result['status'], 'EXPIRED')
        code, _ = server._decide_demo_request(req['id'], 'APPROVED', self.admin)
        self.assertEqual(code, 409)

    def test_rate_limit_and_request_validation(self):
        self.assertEqual(self.request(name='x')[0], 400)
        results = [self.request(key=str(uuid.uuid4()))[0] for _ in range(7)]
        self.assertEqual(results[:6], [201] * 6)
        self.assertEqual(results[6], 429)

    def test_unauthenticated_cookie_cannot_authorize_admin(self):
        self.assertIsNone(server._admin_session(''))
        self.assertIsNone(server._admin_session('forged.cookie', 'csrf'))
        self.assertTrue(server._demo_enabled())


    def test_signed_admin_cookie_and_csrf_gate(self):
        sid, csrf, exp, expiry = server._create_admin_session('Presenter')
        cookie = server._cookie_make(sid, csrf, exp)
        self.assertEqual(server._admin_session(cookie)['admin_name'], 'Presenter')
        self.assertIsNone(server._admin_session(cookie, 'wrong-token'))
        handler = object.__new__(server.Handler)
        handler.headers = {'Host': 'localhost:8080', 'X-CSRF-Token': ''}
        calls = []
        handler.send_json = lambda data, status=200, extra_headers=None: calls.append((data, status))
        self.assertIsNone(handler._require_admin(mutate=True))
        self.assertEqual(calls[-1][1], 401)
        handler.headers['Cookie'] = f'{server.ADMIN_COOKIE}={cookie}'
        self.assertIsNone(handler._require_admin(mutate=True))
        self.assertEqual(calls[-1][1], 403)
        handler.headers['X-CSRF-Token'] = csrf
        self.assertEqual(handler._require_admin(mutate=True)['admin_name'], 'Presenter')

    def test_scoped_reset_preserves_seed_data_and_audit(self):
        _, req = self.request()
        code, result = server._reset_demo_session(self.session_id, self.admin)
        self.assertEqual(code, 200)
        self.assertEqual(result['removed_requests'], 1)
        with self.db() as c:
            seeded = server._load_record(c, 'events', 'EV-201')
            synthetic = server._load_record(c, 'events', req['event_id'])
            audit_count = server._db(c, "SELECT COUNT(*) AS n FROM records WHERE kind='audit'", ()).fetchone()['n']
            remaining = server._db(c, 'SELECT COUNT(*) AS n FROM demo_login_requests WHERE session_id=?', (self.session_id,)).fetchone()['n']
        self.assertIsNotNone(seeded)
        self.assertIsNone(synthetic)
        self.assertEqual(remaining, 0)
        self.assertGreaterEqual(audit_count, 2)


    def test_local_lan_presentation_restricts_general_workspace_writes_to_host(self):
        handler = object.__new__(server.Handler)
        handler.client_address = ('192.168.1.42', 54000)
        self.assertFalse(handler._legacy_local_write_allowed())
        handler.client_address = ('127.0.0.1', 54001)
        self.assertTrue(handler._legacy_local_write_allowed())

    def test_demo_url_never_uses_localhost_for_another_device(self):
        self.assertEqual(server._demo_login_url('http://192.168.1.25:8080', 'session-1'),
                         'http://192.168.1.25:8080/demo-login?session=session-1&api=local')
        server.DEMO_PUBLIC_BASE_URL = 'http://localhost:8080'
        self.assertEqual(server._valid_public_base(), '')


if __name__ == '__main__':
    unittest.main()
