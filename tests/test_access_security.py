from pathlib import Path
import os, json, threading, urllib.request, urllib.error, http.cookiejar, unittest, uuid
from unittest import mock
from http.server import ThreadingHTTPServer
import server

class AccessSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.originals={name:getattr(server,name) for name in ('DB','DATABASE_URL','DEMO_ADMIN_PASSWORD','DEMO_SESSION_SECRET','WORKSPACE_ACCESS_PASSPHRASE','CYBERRAKSHAK_PASSPHRASE','ALLOWED_ORIGIN')}
        cls.test_dir=Path(server.ROOT)/'.test-access-runtime';cls.test_dir.mkdir(exist_ok=True)
    @classmethod
    def tearDownClass(cls):
        for name,value in cls.originals.items():setattr(server,name,value)
        for f in cls.test_dir.glob('*.sqlite3'):f.unlink(missing_ok=True)
        try:cls.test_dir.rmdir()
        except OSError:pass
    def setUp(self):
        server.DATABASE_URL='';server.DB=self.test_dir/(uuid.uuid4().hex+'.sqlite3')
        server.DEMO_ADMIN_PASSWORD='test-only-admin-password-long-enough';server.DEMO_SESSION_SECRET=b'test-secret-for-session-auth-at-least-32-bytes'
        server.CYBERRAKSHAK_PASSPHRASE='CyberAI';server.WORKSPACE_ACCESS_PASSPHRASE='CyberAI';server.ALLOWED_ORIGIN=''
        for name in ('SMTP_HOST','SMTP_PORT','SMTP_USERNAME','SMTP_PASSWORD','ALERT_FROM_EMAIL','ALERT_TO_EMAIL'):os.environ.pop(name,None)
        server.migrate();server.seed()
        self.httpd=ThreadingHTTPServer(('127.0.0.1',0),server.Handler);self.thread=threading.Thread(target=self.httpd.serve_forever,daemon=True);self.thread.start()
        self.base=f'http://127.0.0.1:{self.httpd.server_port}'
        self.opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def tearDown(self):
        self.httpd.shutdown();self.httpd.server_close();self.thread.join(timeout=2);server.DB.unlink(missing_ok=True)
    def request(self,path,method='GET',body=None,headers=None,opener=None):
        req=urllib.request.Request(self.base+path,data=json.dumps(body).encode() if body is not None else None,headers={'Content-Type':'application/json',**(headers or {})},method=method)
        try:
            with (opener or self.opener).open(req,timeout=5) as response:return response.status,json.loads(response.read()),response.headers
        except urllib.error.HTTPError as exc:return exc.code,json.loads(exc.read()),exc.headers
    def test_fresh_invalid_then_correct_passphrase_creates_protected_session(self):
        code,_data,_=self.request('/api/assets');self.assertEqual(code,401)
        self.assertEqual(self.request('/api/access/passphrase','POST',{'passphrase':'wrong'})[0],401)
        self.assertEqual(self.request('/api/access/passphrase','POST',{'passphrase':'wrong'})[0],401)
        code,body,_=self.request('/api/access/passphrase','POST',{'passphrase':'CyberAI'});self.assertEqual(code,200);self.assertIn('csrfToken',body)
        code,session,_=self.request('/api/access/session');self.assertEqual(code,200);self.assertEqual(session['role'],'asset-manager')
        self.assertEqual(self.request('/api/access/admin/security-events')[0],401)
        code,assets,_=self.request('/api/assets');self.assertEqual(code,200);self.assertTrue(assets)
        with server.connect() as c:
            self.assertEqual(server._db(c,"SELECT COUNT(*) AS n FROM records WHERE kind='audit' AND body LIKE '%Passphrase-verified asset-management workspace session established%'",()).fetchone()['n'],1)
            self.assertEqual(server._db(c,'SELECT COUNT(*) AS n FROM access_passphrase_failures',()).fetchone()['n'],0)
    def test_three_failures_persist_event_email_failure_and_throttle(self):
        os.environ.update({'SMTP_HOST':'smtp.gmail.com','SMTP_PORT':'587','SMTP_USERNAME':'owner@gmail.com','SMTP_PASSWORD':'not-a-real-secret','ALERT_FROM_EMAIL':'owner@gmail.com','ALERT_TO_EMAIL':'owner@gmail.com'})
        with mock.patch.object(server.smtplib,'SMTP',side_effect=OSError('secret-looking SMTP detail')) as smtp:
            self.assertEqual([self.request('/api/access/passphrase','POST',{'passphrase':'bad'})[0] for _ in range(2)],[401,401])
            code,third,_=self.request('/api/access/passphrase','POST',{'passphrase':'bad'});self.assertEqual(code,401);self.assertEqual(third['failedAttempts'],3)
            self.request('/api/access/passphrase','POST',{'passphrase':'bad'});code,blocked,_=self.request('/api/access/passphrase','POST',{'passphrase':'bad'});self.assertEqual(code,429);self.assertEqual(blocked['failedAttempts'],5)
            self.assertEqual(self.request('/api/access/passphrase','POST',{'passphrase':'CyberAI'})[0],429)
            self.assertEqual(smtp.call_count,1)
        with server.connect() as c:
            event=server._db(c,'SELECT * FROM access_security_events',()).fetchone();self.assertEqual(event['failed_count'],5);self.assertEqual(event['email_status'],'FAILED');self.assertEqual(event['email_error'],'OSError');self.assertEqual(event['source_ip'],'127.0.0.1')
            self.assertEqual(server._db(c,"SELECT COUNT(*) AS n FROM records WHERE kind='audit' AND body LIKE '%repeated access passphrase failures%'",()).fetchone()['n'],1)
        # Security event details are not disclosed to an unauthenticated visitor; owner can review them.
        self.assertEqual(self.request('/api/access/admin/security-events')[0],401)
        code,login,_=self.request('/api/demo/admin/login','POST',{'password':server.DEMO_ADMIN_PASSWORD});self.assertEqual(code,200)
        code,alerts,_=self.request('/api/access/admin/security-events');self.assertEqual(code,200);self.assertEqual(alerts['events'][0]['failedCount'],5)
    def test_smtp_success_is_reported_only_when_provider_accepts(self):
        os.environ.update({'SMTP_HOST':'smtp.gmail.com','SMTP_PORT':'587','SMTP_USERNAME':'owner@gmail.com','SMTP_PASSWORD':'app-password','ALERT_FROM_EMAIL':'owner@gmail.com','ALERT_TO_EMAIL':'manroopkaur1307@gmail.com'})
        smtp=mock.MagicMock();smtp.__enter__.return_value=smtp
        with mock.patch.object(server.smtplib,'SMTP',return_value=smtp) as factory:
            for _ in range(3):self.request('/api/access/passphrase','POST',{'passphrase':'bad'})
        self.assertEqual(factory.call_count,1);self.assertEqual(smtp.send_message.call_count,1)
        message=smtp.send_message.call_args.args[0];self.assertEqual(message['Subject'],'CyberRakshak AI — Security Alert: Failed Login Attempts');self.assertIn('3 consecutive unsuccessful',message.get_content());self.assertIn('manroopkaur1307@gmail.com',message['To'])
        with server.connect() as c:self.assertEqual(server._db(c,'SELECT email_status FROM access_security_events',()).fetchone()['email_status'],'SENT')
    def test_success_resets_counter_but_retains_prior_alert_history(self):
        for _ in range(3):self.request('/api/access/passphrase','POST',{'passphrase':'bad'})
        self.assertEqual(self.request('/api/access/passphrase','POST',{'passphrase':'CyberAI'})[0],200)
        with server.connect() as c:
            self.assertEqual(server._db(c,'SELECT COUNT(*) AS n FROM access_passphrase_failures',()).fetchone()['n'],0)
            self.assertEqual(server._db(c,'SELECT COUNT(*) AS n FROM access_security_events',()).fetchone()['n'],1)
    def test_origin_mismatch_is_rejected_and_exact_origin_gets_cors(self):
        server.ALLOWED_ORIGIN='https://cyberrakshakai.vercel.app'
        code,body,_=self.request('/api/access/passphrase','POST',{'passphrase':'CyberAI'},{'Origin':'https://wrong.example'});self.assertEqual(code,403);self.assertIn('ALLOWED_ORIGIN',body['error'])
        code,_body,headers=self.request('/api/access/config',headers={'Origin':server.ALLOWED_ORIGIN});self.assertEqual(code,200);self.assertEqual(headers.get('Access-Control-Allow-Origin'),server.ALLOWED_ORIGIN)

if __name__=='__main__':unittest.main()
