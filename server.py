"""CyberRakshak AI local demo server. All security actions are simulated."""
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import json, sqlite3, os, threading, base64, hashlib, hmac, ipaddress, io, re, secrets, time, uuid
import smtplib, ssl
from email.message import EmailMessage
from datetime import datetime, timezone, timedelta
from urllib.parse import urlsplit, urlunsplit, urlencode, parse_qs
from http.cookies import SimpleCookie

ROOT = Path(__file__).parent
DATABASE_URL = os.environ.get('DATABASE_URL', '').strip()
DB = Path(os.environ.get('DATABASE_PATH', str(ROOT / 'cyberrakshak.sqlite3')))
ALLOWED_ORIGIN = os.environ.get('ALLOWED_ORIGIN', 'https://cyberrakshakai.vercel.app').rstrip('/')
DEMO_ADMIN_PASSWORD = os.environ.get('DEMO_ADMIN_PASSWORD', '')
CYBERRAKSHAK_PASSPHRASE = os.environ.get('CYBERRAKSHAK_PASSPHRASE', '')
# Keep the previously configured value working during the environment-variable
# transition. New deployments should set CYBERRAKSHAK_PASSPHRASE.
WORKSPACE_ACCESS_PASSPHRASE = CYBERRAKSHAK_PASSPHRASE or os.environ.get('WORKSPACE_ACCESS_PASSPHRASE', '')
DEMO_SESSION_SECRET = os.environ.get('DEMO_SESSION_SECRET', '').encode('utf-8')
DEMO_ADMIN_NAME = (os.environ.get('DEMO_ADMIN_NAME', 'CyberRakshak presenter').strip() or 'CyberRakshak presenter')[:80]
DEMO_PUBLIC_BASE_URL = os.environ.get('DEMO_PUBLIC_BASE_URL', '').strip()
def _bounded_int(name, default, low, high):
    try: value=int(os.environ.get(name, str(default)))
    except (TypeError, ValueError): value=default
    return max(low, min(high, value))
DEMO_REQUEST_TTL = _bounded_int('DEMO_REQUEST_TTL_SECONDS',180,30,600)
DEMO_SESSION_TTL = _bounded_int('DEMO_SESSION_TTL_SECONDS',1800,300,7200)
ADMIN_COOKIE = 'cr_demo_admin'
ACCESS_COOKIE = 'cr_workspace_access'
ACCESS_VERIFY_COOKIE = 'cr_access_verified'
ACCESS_SCOPE = 'asset-management'
ACCESS_CONTEXT_TTL = 86400
ACCESS_VERIFY_TTL = 3600
ACCESS_FAILURE_LIMIT = 5
ACCESS_FAILURE_BLOCK_SECONDS = 900
ACCESS_FAILURE_WINDOW_SECONDS = 900
LOCK = threading.RLock()
TABLES = ('assets','findings','events','correlations','investigations','remediations','audit','settings')

def connect():
    if DATABASE_URL:
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError('DATABASE_URL is set but psycopg is missing; install requirements.txt') from exc
        return psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=8, sslmode='require')
    c=sqlite3.connect(DB, timeout=8, factory=ClosingConnection); c.row_factory=sqlite3.Row
    return c

class ClosingConnection(sqlite3.Connection):
    """Make `with connect()` release the SQLite file handle after each unit of work."""
    def __exit__(self, exc_type, exc_value, traceback):
        try: return super().__exit__(exc_type, exc_value, traceback)
        finally: self.close()

def migrate():
    """Apply ordered, idempotent SQLite/PostgreSQL schema migrations."""
    migration_dir=ROOT/'migrations'
    with connect() as c:
        if DATABASE_URL:
            c.execute('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP)')
            applied={r['version'] for r in c.execute('SELECT version FROM schema_migrations').fetchall()}
        else:
            c.execute('CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)')
            applied={r['version'] for r in c.execute('SELECT version FROM schema_migrations').fetchall()}
        suffix='postgres' if DATABASE_URL else 'sqlite'
        for version in (1,2,3,4):
            if version in applied: continue
            name={1:'create_records',2:'demo_login_approval',3:'workspace_access',4:'access_security_events'}[version]
            path=migration_dir/(f'{version:03d}_{name}.{suffix}.sql')
            for statement in path.read_text(encoding='utf-8').split(';'):
                if statement.strip(): c.execute(statement)
            marker='%s' if DATABASE_URL else '?'
            c.execute(f'INSERT INTO schema_migrations(version) VALUES ({marker})',(version,))

def seed():
    with LOCK, connect() as c:
        if c.execute('SELECT count(*) AS count FROM records').fetchone()['count']: return
        initial={
        'assets':[
          {'id':'AST-01','name':'Reception-WS-01','type':'Workstation','owner':'Front desk','software':'Windows 11 · Defender','criticality':'Medium','status':'Monitored','observed':'2026-10-02 09:14'},
          {'id':'AST-02','name':'Clinical-Server-01','type':'Server','owner':'IT operations','software':'Ubuntu 22.04 · OpenSSH','criticality':'Critical','status':'Monitored','observed':'2026-10-02 09:12'},
          {'id':'AST-03','name':'Edge-Router-01','type':'Network device','owner':'IT operations','software':'RouterOS 7.14','criticality':'High','status':'Monitored','observed':'2026-10-02 08:55'},
          {'id':'AST-04','name':'Practice-Portal','type':'Application','owner':'Patient services','software':'Clinic portal · v3.8','criticality':'High','status':'Monitored','observed':'2026-10-02 09:02'},
          {'id':'AST-05','name':'Billing-WS-02','type':'Workstation','owner':'Finance','software':'Windows 11 · Defender','criticality':'Medium','status':'Monitored','observed':'2026-10-02 08:48'}],
        'findings':[
          {'id':'FND-101','title':'Repeated failed SSH logins','description':'Several failed authentication attempts were recorded against the clinical server. This signal alone does not establish unauthorized access.','severity':'High','status':'Open','assetId':'AST-02','source':'Endpoint monitor (simulated)','detected':'2026-10-02 08:42','reliability':'High','evidence':['EV-201','EV-202'],'next':'Review authentication logs for a successful session from the same source.'},
          {'id':'FND-102','title':'Router firmware update available','description':'The edge router reports a vendor firmware update. Current version and exposure should be confirmed before scheduling.','severity':'Medium','status':'Open','assetId':'AST-03','source':'Configuration review (simulated)','detected':'2026-10-02 08:10','reliability':'Medium','evidence':['EV-203'],'next':'Confirm the installed firmware and maintenance window.'},
          {'id':'FND-103','title':'Unusual portal sign-in time','description':'A sign-in occurred outside the clinic’s usual operating window. Identity and session context are not yet available.','severity':'Medium','status':'Under review','assetId':'AST-04','source':'Application log (simulated)','detected':'2026-10-02 07:56','reliability':'Medium','evidence':['EV-204'],'next':'Validate with the account owner and review session details.'}],
        'events':[
          {'id':'EV-201','name':'SSH authentication failure','time':'2026-10-02 08:39','assetId':'AST-02','type':'Authentication','severity':'Medium','reliability':'High','description':'Five failed SSH attempts from 198.51.100.24 in a short interval.','evidence':'Simulated auth log · line 1842'},
          {'id':'EV-202','name':'SSH authentication failure','time':'2026-10-02 08:41','assetId':'AST-02','type':'Authentication','severity':'Medium','reliability':'High','description':'Three additional failed SSH attempts from 198.51.100.24. No successful login is present in this sample.','evidence':'Simulated auth log · line 1849'},
          {'id':'EV-203','name':'Firmware advisory detected','time':'2026-10-02 08:10','assetId':'AST-03','type':'Configuration','severity':'Low','reliability':'Medium','description':'A simulated inventory check reports a newer router firmware.','evidence':'Simulated inventory snapshot'},
          {'id':'EV-204','name':'After-hours portal sign-in','time':'2026-10-02 07:56','assetId':'AST-04','type':'Application','severity':'Medium','reliability':'Medium','description':'Sign-in outside expected hours; account owner and source context not included.','evidence':'Simulated portal audit sample'}],
        'correlations':[
          {'id':'COR-01','source':'EV-201','target':'FND-101','type':'supports finding','classification':'Verified','evidence':['Same asset AST-02','Matching event type and timestamp window','Source address 198.51.100.24 recorded in the event'],'missing':['Successful-session audit to assess access outcome'],'explanation':'The event is directly referenced by the finding and shares its affected asset and time window. This verifies the evidence relationship, not compromise.','evaluated':'2026-10-02 09:20'},
          {'id':'COR-02','source':'FND-101','target':'AST-02','type':'affects asset','classification':'Verified','evidence':['Finding explicitly identifies AST-02'],'missing':[],'explanation':'The finding names this asset directly.','evaluated':'2026-10-02 09:20'},
          {'id':'COR-03','source':'FND-103','target':'EV-201','type':'possible shared activity','classification':'Unsupported','evidence':['Both are security events in the same workspace'],'missing':['Shared identity or account','Matching source address or session identifier','Evidence connecting the portal and server'],'explanation':'A shared workspace and nearby timestamps are not enough to establish a relationship. Keep these records separate.','evaluated':'2026-10-02 09:20'},
          {'id':'COR-04','source':'EV-203','target':'AST-03','type':'observed on','classification':'Potential','evidence':['Inventory event names router model family'],'missing':['Device identifier in the advisory payload','Independent confirmation of installed version'],'explanation':'The event likely concerns this router, but the sample lacks a unique device identifier.','evaluated':'2026-10-02 09:20'}],
        'investigations':[{'id':'INV-301','title':'Review repeated SSH failures','status':'Open','priority':'High','links':['FND-101','AST-02','EV-201','EV-202'],'notes':[],'createdBy':'System demo','created':'2026-10-02 09:20','updated':'2026-10-02 09:20','next':'Review authentication logs for a successful session.'}],
        'remediations':[{'id':'REM-401','findingId':'FND-101','title':'Restrict SSH access to approved administrator network','action':'Review and stage an SSH allowlist policy for the clinical server. This is a plan only; no device configuration will change.','reason':'Repeated failed logins warrant validating exposure and access controls.','benefit':'Could reduce unsolicited SSH attempts if access is unnecessarily exposed.','impact':'Administrators outside the approved network may lose access if the allowlist is inaccurate.','risks':'Incorrect rules can interrupt support access. Confirm a tested recovery path and maintenance window.','preconditions':'Confirm approved administrator source ranges and server access owner.','criteria':'A subsequent simulated policy review shows only approved source ranges, and an administrator confirms access.','status':'Pending Approval','findingTitle':'Repeated failed SSH logins'}],
        'settings':[{'id':'workspace','name':'Northstar Dental Clinic','organization':'Northstar Dental Clinic','windowHours':24,'verifiedRule':'Direct entity reference plus corroborating evidence','potentialRule':'Plausible match with at least one explicit missing evidence item','simulationMode':True}]
        }
        for k,rows in initial.items():
            for x in rows:
                if DATABASE_URL:c.execute('INSERT INTO records(kind,id,body) VALUES (%s,%s,%s)',(k,x['id'],json.dumps(x)))
                else:c.execute('INSERT INTO records(kind,id,body) VALUES (?,?,?)',(k,x['id'],json.dumps(x)))


def _now(): return datetime.now(timezone.utc).isoformat(timespec='seconds')
def _parse_time(value):
    try: return datetime.fromisoformat(str(value).replace('Z','+00:00'))
    except (TypeError,ValueError): return datetime.min.replace(tzinfo=timezone.utc)
def _expired(value): return _parse_time(value) <= datetime.now(timezone.utc)
def _db(c,sql,params=()): return c.execute(sql.replace('?','%s') if DATABASE_URL else sql,params)
def _dict(row): return dict(row) if row is not None else None
def _demo_enabled(): return len(DEMO_ADMIN_PASSWORD)>=20 and len(DEMO_SESSION_SECRET)>=32
def _workspace_access_enabled():return _demo_enabled() and bool(WORKSPACE_ACCESS_PASSPHRASE)
def _access_verification_cookie(expiry):
    payload=json.dumps({'scope':'request','exp':expiry,'nonce':secrets.token_urlsafe(24)},separators=(',',':')).encode();raw=base64.urlsafe_b64encode(payload).rstrip(b'=').decode();sig=base64.urlsafe_b64encode(hmac.new(DEMO_SESSION_SECRET,('workspace-access-verified|'+raw).encode(),hashlib.sha256).digest()).rstrip(b'=').decode();return raw+'.'+sig
def _access_verification_valid(cookie_value):
    if not _workspace_access_enabled() or not cookie_value:return False
    try:
        raw,sig=cookie_value.split('.',1);expected=base64.urlsafe_b64encode(hmac.new(DEMO_SESSION_SECRET,('workspace-access-verified|'+raw).encode(),hashlib.sha256).digest()).rstrip(b'=').decode()
        if not hmac.compare_digest(sig,expected):return False
        payload=json.loads(base64.urlsafe_b64decode(raw+'='*((4-len(raw)%4)%4)))
        return payload.get('scope')=='request' and int(payload.get('exp',0))>int(time.time())
    except Exception:return False
def _valid_public_base():
    try:
        p=urlsplit(DEMO_PUBLIC_BASE_URL)
        if p.scheme not in ('https','http') or not p.hostname or p.username or p.password or p.path not in ('','/') or p.query or p.fragment: return ''
        host=p.hostname.lower()
        if host in ('localhost','localhost.localdomain'): return ''
        if p.scheme=='http':
            try:
                address=ipaddress.ip_address(host)
                if not (address.is_private and not address.is_loopback and not address.is_link_local): return ''
            except ValueError: return ''
        return f'{p.scheme}://{p.netloc}'
    except Exception: return ''
def _demo_login_url(base,session_id):
    params={'session':session_id}
    if base.startswith('http://'): params['api']='local'
    return urlunsplit((*urlsplit(base)[:2],'/demo-login',urlencode(params),''))
def _access_request_url(base,context_id):
    params={'context':context_id}
    if base.startswith('http://'):params['api']='local'
    return urlunsplit((*urlsplit(base)[:2],'/access-request',urlencode(params),''))
def _store_record(c,kind,obj):
    body=json.dumps(obj,ensure_ascii=False)
    if DATABASE_URL: _db(c,'INSERT INTO records(kind,id,body) VALUES (?,?,?) ON CONFLICT(kind,id) DO UPDATE SET body=EXCLUDED.body',(kind,obj['id'],body))
    else: _db(c,'INSERT OR REPLACE INTO records(kind,id,body) VALUES (?,?,?)',(kind,obj['id'],body))
def _load_record(c,kind,rid):
    row=_db(c,'SELECT body FROM records WHERE kind=? AND id=?',(kind,rid)).fetchone()
    return json.loads(row['body']) if row else None
def _audit_record(c,action,entity,entity_id,description,previous=None,new=None,actor='Workspace analyst'):
    rec={'id':'AUD-'+str(time.time_ns()),'time':_now(),'actor':actor,'action':action,'entityType':entity,'entityId':entity_id,'description':description,'previous':previous,'new':new,'origin':'User'}
    _store_record(c,'audit',rec);return rec
def _status_row(row):
    return {'id':row['id'],'session_id':row['session_id'],'display_name':row['display_name'],'status':row['status'],'created_at':row['created_at'],'expires_at':row['expires_at'],'decided_at':row['decided_at'],'event_id':row['event_id']}
def _expire_request(c,row):
    req=_dict(row)
    if req and req['status']=='PENDING' and _expired(req['expires_at']):
        req['status']='EXPIRED';_db(c,"UPDATE demo_login_requests SET status='EXPIRED' WHERE id=? AND status='PENDING'",(req['id'],))
        event=_load_record(c,'events',req['event_id'])
        if event: event['status']='EXPIRED';event['description']='Synthetic demo access request expired without a decision.';_store_record(c,'events',event)
        _audit_record(c,'demo access request expired','demo_login_request',req['id'],f"Synthetic demo request {req['id']} expired",new={'status':'EXPIRED','event_id':req['event_id']},actor='System')
    return req
def _expire_session(c,row):
    session=_dict(row)
    if session and session['status']=='ACTIVE' and _expired(session['expires_at']):
        _db(c,"UPDATE demo_sessions SET status='EXPIRED' WHERE id=? AND status='ACTIVE'",(session['id'],))
        pending=_db(c,"SELECT * FROM demo_login_requests WHERE session_id=? AND status='PENDING'",(session['id'],)).fetchall()
        for req in pending:
            req=_dict(req); _db(c,"UPDATE demo_login_requests SET status='EXPIRED' WHERE id=? AND status='PENDING'",(req['id'],))
            event=_load_record(c,'events',req['event_id'])
            if event: event['status']='EXPIRED'; event['description']='Synthetic demo access request expired because its demo session ended.'; _store_record(c,'events',event)
            _audit_record(c,'demo access request expired','demo_login_request',req['id'],f"Synthetic demo request {req['id']} expired with its session",new={'status':'EXPIRED','event_id':req['event_id']},actor='System')
        _audit_record(c,'demo session expired','demo_session',session['id'],f"Live demo session {session['id']} expired",new={'status':'EXPIRED'},actor='System')
        session['status']='EXPIRED'
    return session
def _expire_pending_for_session(c,session_id,reason):
    pending=_db(c,"SELECT * FROM demo_login_requests WHERE session_id=? AND status='PENDING'",(session_id,)).fetchall()
    for row in pending:
        req=_dict(row);_db(c,"UPDATE demo_login_requests SET status='EXPIRED' WHERE id=? AND status='PENDING'",(req['id'],))
        event=_load_record(c,'events',req['event_id'])
        if event:event['status']='EXPIRED';event['description']=f'Synthetic demo access request expired because {reason}.';_store_record(c,'events',event)
        _audit_record(c,'demo access request expired','demo_login_request',req['id'],f"Synthetic demo request {req['id']} expired because {reason}",new={'status':'EXPIRED','event_id':req['event_id']},actor='System')
def _rate_key(client,action):
    key=DEMO_SESSION_SECRET or b'cyberrakshak-demo-rate-limit-disabled-auth'
    return hmac.new(key,(action+'|'+client).encode(),hashlib.sha256).hexdigest()
def _rate_allowed(client,action,limit,window_seconds):
    now=datetime.now(timezone.utc);cutoff=(now-timedelta(seconds=window_seconds)).isoformat(timespec='seconds');stamp=now.isoformat(timespec='seconds');bucket=_rate_key(client,action)
    with LOCK,connect() as c:
        _db(c,'DELETE FROM demo_rate_limits WHERE created_at < ?',( (now-timedelta(days=1)).isoformat(timespec='seconds'),))
        count=_db(c,'SELECT COUNT(*) AS n FROM demo_rate_limits WHERE bucket_key=? AND action=? AND created_at>=?',(bucket,action,cutoff)).fetchone()['n']
        if count>=limit:return False
        _db(c,'INSERT INTO demo_rate_limits(bucket_key,action,created_at) VALUES (?,?,?)',(bucket,action,stamp))
    return True
def _cookie_make(sid,csrf,exp):
    payload=json.dumps({'sid':sid,'csrf':csrf,'exp':exp},separators=(',',':')).encode();raw=base64.urlsafe_b64encode(payload).rstrip(b'=').decode();sig=base64.urlsafe_b64encode(hmac.new(DEMO_SESSION_SECRET,raw.encode(),hashlib.sha256).digest()).rstrip(b'=').decode();return raw+'.'+sig
def _admin_session(cookie_value,csrf_header=''):
    if not _demo_enabled() or not cookie_value:return None
    try:
        raw,sig=cookie_value.split('.',1);expected=base64.urlsafe_b64encode(hmac.new(DEMO_SESSION_SECRET,raw.encode(),hashlib.sha256).digest()).rstrip(b'=').decode()
        if not hmac.compare_digest(sig,expected):return None
        payload=json.loads(base64.urlsafe_b64decode(raw+'='*((4-len(raw)%4)%4)))
        if int(payload['exp'])<=int(time.time()):return None
        with LOCK,connect() as c: row=_db(c,'SELECT * FROM demo_admin_sessions WHERE id=?',(payload['sid'],)).fetchone()
        if not row or row['revoked_at'] or _expired(row['expires_at']):return None
        if not hmac.compare_digest(hashlib.sha256(payload['csrf'].encode()).hexdigest(),row['csrf_hash']):return None
        if csrf_header and not hmac.compare_digest(payload['csrf'],csrf_header):return None
        result=_dict(row);result['csrf']=payload['csrf'];result['expires_epoch']=int(payload['exp']);return result
    except Exception:return None
def _normalize_display_name(value):
    if not isinstance(value,str):return ''
    value=' '.join(value.split())
    if not 2<=len(value)<=48 or any(ord(ch)<32 or ord(ch)==127 for ch in value):return ''
    return value
def _new_demo_event(req_id,display_name,event_id,created_at,status='PENDING'):
    return {'id':event_id,'name':'Synthetic demo access request','time':created_at,'assetId':None,'type':'Demo access request','severity':'Low','reliability':'High','status':status,'description':f"Fictional access request from {display_name}. This is a synthetic presentation event, not a real login attempt or security incident.",'evidence':f"Demo request {req_id}",'source':'CyberRakshak QR live demo','simulated':True,'demoRequestId':req_id}
def _expire_request_by_id(req_id):
    with LOCK,connect() as c:
        row=_db(c,'SELECT * FROM demo_login_requests WHERE id=?',(req_id,)).fetchone()
        return _status_row(_expire_request(c,row)) if row else None
def _create_demo_request(session_id,display_name,idempotency_key,client):
    name=_normalize_display_name(display_name)
    if not name: return (400,{'error':'Enter a fictional display name between 2 and 48 characters.'})
    if not re.fullmatch(r'[A-Fa-f0-9-]{32,36}',str(idempotency_key or '')):return (400,{'error':'A valid request retry key is required.'})
    if not _rate_allowed(client,'public-create',6,60):return (429,{'error':'Too many demo requests from this connection. Please wait before retrying.'})
    now=datetime.now(timezone.utc);stamp=now.isoformat(timespec='seconds');rid='DRQ-'+uuid.uuid4().hex;event_id='EV-LOGIN-'+uuid.uuid4().hex[:20]
    with LOCK,connect() as c:
        session=_db(c,'SELECT * FROM demo_sessions WHERE id=?',(session_id,)).fetchone()
        if not session or session['status']!='ACTIVE':return (410,{'error':'This demo session is closed or unavailable.'})
        _expire_session(c,session)
        session=_db(c,'SELECT * FROM demo_sessions WHERE id=?',(session_id,)).fetchone()
        if not session or session['status']!='ACTIVE':return (410,{'error':'This demo session has expired.'})
        prior=_db(c,'SELECT * FROM demo_login_requests WHERE session_id=? AND idempotency_key=?',(session_id,idempotency_key)).fetchone()
        if prior:return (200,_status_row(_expire_request(c,prior)))
        pending=_db(c,"SELECT COUNT(*) AS n FROM demo_login_requests WHERE session_id=? AND status='PENDING' AND expires_at>?",(session_id,stamp)).fetchone()['n']
        if pending>=10:return (429,{'error':'This demo session already has its maximum pending requests.'})
        exp=min(now+timedelta(seconds=DEMO_REQUEST_TTL),_parse_time(session['expires_at']))
        expiry=exp.isoformat(timespec='seconds')
        req={'id':rid,'session_id':session_id,'idempotency_key':idempotency_key,'display_name':name,'status':'PENDING','created_at':stamp,'expires_at':expiry,'decided_at':None,'decided_by':None,'event_id':event_id}
        _db(c,'INSERT INTO demo_login_requests(id,session_id,idempotency_key,display_name,status,created_at,expires_at,decided_at,decided_by,event_id) VALUES (?,?,?,?,?,?,?,?,?,?)',(rid,session_id,idempotency_key,name,'PENDING',stamp,expiry,None,None,event_id))
        _store_record(c,'events',_new_demo_event(rid,name,event_id,stamp))
        _audit_record(c,'demo access request submitted','demo_login_request',rid,f"Synthetic QR demo request from {name}",new={'status':'PENDING','event_id':event_id},actor='Demo participant')
    return (201,_status_row(req))
def _decide_demo_request(req_id,decision,admin):
    if decision not in ('APPROVED','DECLINED'):return (400,{'error':'Decision must be Approved or Declined.'})
    now=_now()
    with LOCK,connect() as c:
        row=_db(c,'SELECT * FROM demo_login_requests WHERE id=?',(req_id,)).fetchone()
        if not row:return (404,{'error':'Demo request not found.'})
        row=_expire_request(c,row);session=_db(c,'SELECT * FROM demo_sessions WHERE id=?',(row['session_id'],)).fetchone();session=_expire_session(c,session)
        current=_db(c,'SELECT * FROM demo_login_requests WHERE id=?',(req_id,)).fetchone()
        if session is None or session['status']!='ACTIVE':return (409,{'error':'Demo session is no longer active.','request':_status_row(current)})
        if current['status']!='PENDING':return (409,{'error':'This request already has a terminal decision.','request':_status_row(current)})
        changed=_db(c,"UPDATE demo_login_requests SET status=?,decided_at=?,decided_by=? WHERE id=? AND status='PENDING' AND expires_at>?",(decision,now,admin['admin_name'],req_id,now)).rowcount
        if changed!=1:
            latest=_db(c,'SELECT * FROM demo_login_requests WHERE id=?',(req_id,)).fetchone();return (409,{'error':'Request expired or was already decided.','request':_status_row(latest)})
        event=_load_record(c,'events',current['event_id'])
        if event:event['status']=decision;event['description']=f"Synthetic demo access request from {current['display_name']} was {decision.lower()} by the presenter. No real account or system access changed.";_store_record(c,'events',event)
        _audit_record(c,'demo access '+decision.lower(),'demo_login_request',req_id,f"Demo request {req_id} for {current['display_name']} was {decision.lower()} by {admin['admin_name']}",previous={'status':'PENDING'},new={'status':decision,'decided_at':now,'decided_by':admin['admin_name'],'event_id':current['event_id']},actor=admin['admin_name'])
        updated=_db(c,'SELECT * FROM demo_login_requests WHERE id=?',(req_id,)).fetchone()
    return (200,_status_row(updated))
def _reset_demo_session(session_id,admin):
    with LOCK,connect() as c:
        session=_db(c,'SELECT * FROM demo_sessions WHERE id=?',(session_id,)).fetchone()
        if not session or session['created_by']!=admin['admin_name']:return (404,{'error':'Demo session not found.'})
        requests=_db(c,'SELECT id,event_id FROM demo_login_requests WHERE session_id=?',(session_id,)).fetchall();event_ids=[r['event_id'] for r in requests]
        for event_id in event_ids:_db(c,"DELETE FROM records WHERE kind='events' AND id=?",(event_id,))
        _db(c,'DELETE FROM demo_login_requests WHERE session_id=?',(session_id,))
        _db(c,"UPDATE demo_sessions SET status='CLOSED' WHERE id=? AND status='ACTIVE'",(session_id,))
        _audit_record(c,'demo session reset','demo_session',session_id,f"Live demo session {session_id} reset; removed {len(requests)} synthetic requests and their events",previous={'status':'ACTIVE'},new={'status':'CLOSED','requests_removed':len(requests)},actor=admin['admin_name'])
    return (200,{'ok':True,'session_id':session_id,'removed_requests':len(requests)})

def _create_admin_session(admin_name):
    now=datetime.now(timezone.utc); sid=secrets.token_urlsafe(24); csrf=secrets.token_urlsafe(32)
    expiry=(now+timedelta(seconds=DEMO_SESSION_TTL)).isoformat(timespec='seconds')
    with LOCK,connect() as c:
        _db(c,'UPDATE demo_admin_sessions SET revoked_at=? WHERE revoked_at IS NULL',(now.isoformat(timespec='seconds'),))
        _db(c,'INSERT INTO demo_admin_sessions(id,csrf_hash,admin_name,created_at,expires_at,revoked_at) VALUES (?,?,?,?,?,NULL)',(sid,hashlib.sha256(csrf.encode()).hexdigest(),admin_name,now.isoformat(timespec='seconds'),expiry))
    return sid,csrf,int((now+timedelta(seconds=DEMO_SESSION_TTL)).timestamp()),expiry

def _access_proof_hash(value):
    return hmac.new(DEMO_SESSION_SECRET,('workspace-access-proof|'+value).encode(),hashlib.sha256).hexdigest()

def _smtp_configuration():
    host=os.environ.get('SMTP_HOST','').strip(); port=_bounded_int('SMTP_PORT',587,1,65535)
    username=os.environ.get('SMTP_USERNAME',''); password=os.environ.get('SMTP_PASSWORD','')
    sender=os.environ.get('ALERT_FROM_EMAIL','').strip(); recipient=os.environ.get('ALERT_TO_EMAIL','').strip()
    if not host or not sender or not recipient:return None
    if bool(username)!=bool(password):return None
    return host,port,username,password,sender,recipient

def _deliver_security_email(event):
    cfg=_smtp_configuration()
    if not cfg:return ('NOT_CONFIGURED','SMTP host/sender/recipient or a complete SMTP username/password pair is missing.')
    host,port,username,password,sender,recipient=cfg
    message=EmailMessage();message['Subject']='CyberRakshak AI — Security Alert: Failed Login Attempts';message['From']=sender;message['To']=recipient
    ip=event.get('source_ip') or 'Unavailable (no trusted direct peer address)'
    message.set_content(f"CyberRakshak AI recorded {event['failed_count']} consecutive unsuccessful passphrase attempts.\n\nTimestamp: {event['occurred_at']} UTC\nSource IP (direct connection peer; forwarded headers are not trusted): {ip}\n\nThe login attempt was unsuccessful. Please review the security audit trail.")
    try:
        if port==465:
            with smtplib.SMTP_SSL(host,port,timeout=8,context=ssl.create_default_context()) as client:
                if username:client.login(username,password)
                client.send_message(message)
        else:
            with smtplib.SMTP(host,port,timeout=8) as client:
                client.ehlo();client.starttls(context=ssl.create_default_context());client.ehlo()
                if username:client.login(username,password)
                client.send_message(message)
        return ('SENT',None)
    except Exception as exc:
        # Exception text may contain server details; keep logs secret-free.
        print(f'Security alert email delivery failed ({type(exc).__name__}).',flush=True)
        return ('FAILED',type(exc).__name__)

def _record_security_email_status(event_id,status,error=None):
    with LOCK,connect() as c:
        stamp=_now() if status=='SENT' else None
        _db(c,'UPDATE access_security_events SET email_status=?,email_error=?,email_sent_at=? WHERE id=?',(status,error,stamp,event_id))

def _create_workspace_passphrase_session(source_ip):
    now=datetime.now(timezone.utc);stamp=now.isoformat(timespec='seconds');sid='WPS-'+uuid.uuid4().hex;identity='WID-'+uuid.uuid4().hex
    token=secrets.token_hex(32);csrf=hmac.new(DEMO_SESSION_SECRET,('workspace-csrf|'+sid+'|'+token).encode(),hashlib.sha256).hexdigest();expiry=(now+timedelta(seconds=DEMO_SESSION_TTL)).isoformat(timespec='seconds')
    with LOCK,connect() as c:
        _db(c,'INSERT INTO workspace_passphrase_sessions(id,identity_id,permission_scope,token_hash,csrf_hash,created_at,expires_at,revoked_at) VALUES (?,?,?,?,?,?,?,NULL)',(sid,identity,ACCESS_SCOPE,hashlib.sha256(token.encode()).hexdigest(),hashlib.sha256(csrf.encode()).hexdigest(),stamp,expiry))
        audit=_audit_record(c,'login','workspace_passphrase_session',sid,'Passphrase-verified asset-management workspace session established.',new={'identity_id':identity,'permission_scope':ACCESS_SCOPE,'session':'established','result':'success'},actor='Passphrase-authenticated workspace user')
    secure=ALLOWED_ORIGIN.startswith('https://');same='None' if secure else 'Strict'
    cookie=f'{ACCESS_COOKIE}={sid}.{token}; Path=/; HttpOnly; SameSite={same}; Max-Age={DEMO_SESSION_TTL}'+('; Secure' if secure else '')
    return {'ok':True,'csrfToken':csrf,'expiresAt':expiry,'identityId':identity,'permissionScope':ACCESS_SCOPE},[('Set-Cookie',cookie)]

def _verify_workspace_passphrase(supplied, source_ip):
    """Verify, apply persisted cooldowns and create a scoped session on success."""
    if not _workspace_access_enabled():return (503,{'error':'Workspace access is not configured. Ask the owner to configure the backend passphrase.'},None)
    now=datetime.now(timezone.utc);stamp=now.isoformat(timespec='seconds');ip=str(source_ip or '')[:64]
    ip_hash=hmac.new(DEMO_SESSION_SECRET,('access-failure-ip|'+ip).encode(),hashlib.sha256).hexdigest();send_event=None
    with LOCK,connect() as c:
        row=_db(c,'SELECT * FROM access_passphrase_failures WHERE ip_hash=?',(ip_hash,)).fetchone()
        if row and row['blocked_until'] and not _expired(row['blocked_until']):return (429,{'error':'Too many incorrect passphrase attempts. Access is temporarily blocked for 15 minutes.','retryAt':row['blocked_until']},None)
        if isinstance(supplied,str) and hmac.compare_digest(supplied,WORKSPACE_ACCESS_PASSPHRASE):
            _db(c,'DELETE FROM access_passphrase_failures WHERE ip_hash=?',(ip_hash,))
            c.commit()
            result,headers=_create_workspace_passphrase_session(ip)
            return (200,result,headers)
        within_window=bool(row and not _expired((datetime.fromisoformat(row['last_failed_at'].replace('Z','+00:00'))+timedelta(seconds=ACCESS_FAILURE_WINDOW_SECONDS)).isoformat(timespec='seconds')))
        count=(row['failed_count']+1) if within_window else 1;first=row['first_failed_at'] if within_window else stamp
        blocked=(now+timedelta(seconds=ACCESS_FAILURE_BLOCK_SECONDS)).isoformat(timespec='seconds') if count>=ACCESS_FAILURE_LIMIT else None
        alert_id=row['alert_event_id'] if within_window and row else None
        if row:_db(c,'UPDATE access_passphrase_failures SET failed_count=?,first_failed_at=?,last_failed_at=?,blocked_until=?,alert_event_id=? WHERE ip_hash=?',(count,first,stamp,blocked,alert_id if within_window else None,ip_hash))
        else:_db(c,'INSERT INTO access_passphrase_failures(ip_hash,failed_count,first_failed_at,last_failed_at,blocked_until,alert_event_id) VALUES (?,?,?,?,?,NULL)',(ip_hash,count,first,stamp,blocked))
        if count>=3:
            if not alert_id:
                alert_id='SEC-'+uuid.uuid4().hex
                _db(c,'INSERT INTO access_security_events(id,failed_count,occurred_at,source_ip,source_ip_hash,blocked_until,email_status) VALUES (?,?,?,?,?,?,?)',(alert_id,count,stamp,ip or None,ip_hash,blocked,'PENDING'))
                _db(c,'UPDATE access_passphrase_failures SET alert_event_id=? WHERE ip_hash=?',(alert_id,ip_hash))
                _audit_record(c,'repeated access passphrase failures','security_event',alert_id,f'{count} consecutive unsuccessful workspace passphrase attempts were recorded',new={'event_id':alert_id,'failed_count':count,'occurred_at':stamp,'blocked_until':blocked},actor='System')
                send_event={'id':alert_id,'failed_count':count,'occurred_at':stamp,'source_ip':ip or None}
            else:
                _db(c,'UPDATE access_security_events SET failed_count=?,occurred_at=?,source_ip=?,blocked_until=? WHERE id=?',(count,stamp,ip or None,blocked,alert_id))
    if send_event:
        status,error=_deliver_security_email(send_event);_record_security_email_status(send_event['id'],status,error)
    if blocked:return (429,{'error':'Too many incorrect passphrase attempts. Access is temporarily blocked for 15 minutes.','retryAt':blocked,'failedAttempts':count},None)
    return (401,{'error':'Invalid access passphrase.','failedAttempts':count},None)

def _security_event_rows():
    with LOCK,connect() as c:
        rows=_db(c,'SELECT id,failed_count,occurred_at,source_ip,blocked_until,email_status,email_error,email_sent_at FROM access_security_events ORDER BY occurred_at DESC LIMIT 50',()).fetchall()
    return [{'id':r['id'],'failedCount':r['failed_count'],'timestamp':r['occurred_at'],'sourceIp':r['source_ip'] or 'Unavailable','blockedUntil':r['blocked_until'],'emailStatus':r['email_status'],'emailError':r['email_error'],'emailSentAt':r['email_sent_at']} for r in rows]

def _access_request_row(row):
    if not row:return None
    r=_dict(row)
    return {'id':r['id'],'context_id':r['context_id'],'identity_id':r['identity_id'],'display_name':r['display_name'],'permission_scope':r['permission_scope'],'status':r['status'],'created_at':r['created_at'],'expires_at':r['expires_at'],'decided_at':r['decided_at'],'decided_by':r['decided_by'],'revoked_at':r['revoked_at']}
def _expire_workspace_request(c,row):
    req=_dict(row)
    if req and req['status']=='PENDING' and _expired(req['expires_at']):
        now=_now();_db(c,"UPDATE workspace_access_requests SET status='EXPIRED' WHERE id=? AND status='PENDING'",(req['id'],))
        _audit_record(c,'workspace access expired','workspace_access_request',req['id'],f"Access request from {req['display_name']} expired without a decision",previous={'status':'PENDING'},new={'status':'EXPIRED','permission_scope':req['permission_scope'],'identity_id':req['identity_id']},actor='System')
        req['status']='EXPIRED';req['decided_at']=now
    if req and req['context_id']:
        context=_db(c,'SELECT * FROM workspace_access_contexts WHERE id=?',(req['context_id'],)).fetchone()
        if context and context['status']=='ACTIVE' and _expired(context['expires_at']):
            _db(c,"UPDATE workspace_access_contexts SET status='EXPIRED' WHERE id=? AND status='ACTIVE'",(req['context_id'],))
            if req['status']=='PENDING':
                now=_now();_db(c,"UPDATE workspace_access_requests SET status='EXPIRED' WHERE id=? AND status='PENDING'",(req['id'],))
                _audit_record(c,'workspace access expired','workspace_access_request',req['id'],f"Access request from {req['display_name']} expired with its access link",previous={'status':'PENDING'},new={'status':'EXPIRED','permission_scope':req['permission_scope'],'identity_id':req['identity_id']},actor='System')
                req['status']='EXPIRED';req['decided_at']=now
    return req
def _create_workspace_access_request(display_name,request_key,context_id,client):
    name=_normalize_display_name(display_name)
    if not name:return (400,{'error':'Enter a display name between 2 and 48 characters.'})
    if not isinstance(request_key,str) or not re.fullmatch(r'[A-Fa-f0-9-]{32,36}',request_key):return (400,{'error':'A valid private request key is required.'})
    if not _workspace_access_enabled():return (503,{'error':'Workspace access passphrase and owner authentication are not configured.'})
    if not _rate_allowed(client,'workspace-access-request',6,300):return (429,{'error':'Too many access requests. Please wait before trying again.'})
    proof_hash=_access_proof_hash(request_key);now=datetime.now(timezone.utc);stamp=now.isoformat(timespec='seconds')
    with LOCK,connect() as c:
        if context_id:
            context=_db(c,'SELECT * FROM workspace_access_contexts WHERE id=?',(context_id,)).fetchone()
            if not context or context['status']!='ACTIVE' or _expired(context['expires_at']):return (410,{'error':'This access request link has expired. Open the current owner link.'})
        prior=_db(c,'SELECT * FROM workspace_access_requests WHERE proof_hash=?',(proof_hash,)).fetchone()
        if prior:return (200,_access_request_row(_expire_workspace_request(c,prior)))
        pending=_db(c,"SELECT COUNT(*) AS n FROM workspace_access_requests WHERE status='PENDING' AND expires_at>?",(stamp,)).fetchone()['n']
        if pending>=100:return (429,{'error':'The workspace has reached its pending access request limit.'})
        req_id='WAR-'+uuid.uuid4().hex;identity_id='WID-'+uuid.uuid4().hex;expiry=(now+timedelta(seconds=DEMO_REQUEST_TTL)).isoformat(timespec='seconds')
        _db(c,'INSERT INTO workspace_access_requests(id,context_id,identity_id,proof_hash,display_name,permission_scope,status,created_at,expires_at,decided_at,decided_by,revoked_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',(req_id,context_id or None,identity_id,proof_hash,name,ACCESS_SCOPE,'PENDING',stamp,expiry,None,None,None))
        _audit_record(c,'workspace access requested','workspace_access_request',req_id,f"{name} requested {ACCESS_SCOPE} access",new={'status':'PENDING','identity_id':identity_id,'permission_scope':ACCESS_SCOPE,'context_id':context_id or None},actor='Requester')
        row=_db(c,'SELECT * FROM workspace_access_requests WHERE id=?',(req_id,)).fetchone()
    return (201,_access_request_row(row))
def _decide_workspace_access(req_id,decision,admin):
    if decision not in ('APPROVED','DECLINED'):return (400,{'error':'Decision must be APPROVED or DECLINED.'})
    now=_now()
    with LOCK,connect() as c:
        row=_db(c,'SELECT * FROM workspace_access_requests WHERE id=?',(req_id,)).fetchone()
        if not row:return (404,{'error':'Workspace access request not found.'})
        req=_expire_workspace_request(c,row);current=_db(c,'SELECT * FROM workspace_access_requests WHERE id=?',(req_id,)).fetchone()
        if current['status']!='PENDING':return (409,{'error':'This request has expired or already has a decision.','request':_access_request_row(current)})
        changed=_db(c,"UPDATE workspace_access_requests SET status=?,decided_at=?,decided_by=? WHERE id=? AND status='PENDING' AND expires_at>?",(decision,now,admin['admin_name'],req_id,now)).rowcount
        if changed!=1:
            latest=_db(c,'SELECT * FROM workspace_access_requests WHERE id=?',(req_id,)).fetchone()
            _expire_workspace_request(c,latest);latest=_db(c,'SELECT * FROM workspace_access_requests WHERE id=?',(req_id,)).fetchone()
            return (409,{'error':'Request expired or another owner decision was recorded.','request':_access_request_row(latest)})
        if decision=='APPROVED':
            _audit_record(c,'workspace access approved','workspace_access_request',req_id,f"{req['display_name']} — asset-management access approved by the workspace owner",previous={'status':'PENDING'},new={'status':'APPROVED','identity_id':req['identity_id'],'permission_scope':req['permission_scope'],'access_granted':True,'session_established':False},actor=admin['admin_name'])
        else:
            _audit_record(c,'workspace access declined','workspace_access_request',req_id,f"{req['display_name']} — asset-management access declined by the workspace owner",previous={'status':'PENDING'},new={'status':'DECLINED','identity_id':req['identity_id'],'permission_scope':req['permission_scope'],'access_granted':False},actor=admin['admin_name'])
        updated=_db(c,'SELECT * FROM workspace_access_requests WHERE id=?',(req_id,)).fetchone()
    return (200,_access_request_row(updated))
def _establish_workspace_access(req_id,request_key):
    if not isinstance(request_key,str) or not re.fullmatch(r'[A-Fa-f0-9-]{32,36}',request_key):return (400,{'error':'The private request proof is missing or invalid.'},None)
    now=datetime.now(timezone.utc);stamp=now.isoformat(timespec='seconds');proof_hash=_access_proof_hash(request_key)
    sid='WAS-'+hashlib.sha256((req_id+'|'+request_key).encode()).hexdigest()[:32]
    token=hmac.new(DEMO_SESSION_SECRET,('workspace-session|'+sid+'|'+request_key).encode(),hashlib.sha256).hexdigest()
    csrf=hmac.new(DEMO_SESSION_SECRET,('workspace-csrf|'+sid+'|'+token).encode(),hashlib.sha256).hexdigest()
    expires=(now+timedelta(seconds=DEMO_SESSION_TTL)).isoformat(timespec='seconds')
    with LOCK,connect() as c:
        row=_db(c,'SELECT * FROM workspace_access_requests WHERE id=?',(req_id,)).fetchone()
        if not row:return (404,{'error':'Access request not found.'},None)
        req=_expire_workspace_request(c,row)
        if not hmac.compare_digest(req['proof_hash'],proof_hash):return (403,{'error':'This request belongs to another browser session.'},None)
        current=_db(c,'SELECT * FROM workspace_access_requests WHERE id=?',(req_id,)).fetchone()
        if current['status']!='APPROVED' or current['revoked_at']:return (409,{'error':'Owner approval is required before workspace access can be established.','request':_access_request_row(current)},None)
        session=_db(c,'SELECT * FROM workspace_access_sessions WHERE id=?',(sid,)).fetchone()
        if session and session['revoked_at']:return (403,{'error':'This access session has been revoked. Request access again.'},None)
        new_login=not session or _expired(session['expires_at'])
        if not session:
            _db(c,'INSERT INTO workspace_access_sessions(id,request_id,identity_id,permission_scope,token_hash,csrf_hash,created_at,expires_at,revoked_at,login_audit_id) VALUES (?,?,?,?,?,?,?,?,?,?)',(sid,req_id,req['identity_id'],req['permission_scope'],hashlib.sha256(token.encode()).hexdigest(),hashlib.sha256(csrf.encode()).hexdigest(),stamp,expires,None,None))
        elif new_login:
            _db(c,'UPDATE workspace_access_sessions SET token_hash=?,csrf_hash=?,created_at=?,expires_at=?,login_audit_id=NULL WHERE id=?',(hashlib.sha256(token.encode()).hexdigest(),hashlib.sha256(csrf.encode()).hexdigest(),stamp,expires,sid))
        elif not hmac.compare_digest(session['token_hash'],hashlib.sha256(token.encode()).hexdigest()):
            return (403,{'error':'The saved access credential is invalid.'},None)
        if new_login:
            audit=_audit_record(c,'login','workspace_access_session',sid,f"{req['display_name']} logged in — asset-management access approved by the workspace owner.",previous={'request_status':'APPROVED','session':'not established'},new={'request_status':'APPROVED','session':'established','identity_id':req['identity_id'],'request_id':req_id,'permission_scope':req['permission_scope'],'result':'success'},actor=req['display_name'])
            _db(c,'UPDATE workspace_access_sessions SET login_audit_id=? WHERE id=?',(audit['id'],sid))
    issued_expiry=expires if new_login else session['expires_at']
    cookie=f'{ACCESS_COOKIE}={sid}.{token}; Path=/; HttpOnly; SameSite={"None" if ALLOWED_ORIGIN.startswith("https://") else "Strict"}; Max-Age={DEMO_SESSION_TTL}'+('; Secure' if ALLOWED_ORIGIN.startswith('https://') else '')
    return (200,{'ok':True,'csrfToken':csrf,'expiresAt':issued_expiry,'identityId':req['identity_id'],'displayName':req['display_name'],'permissionScope':req['permission_scope']},[('Set-Cookie',cookie)])
def _decide_workspace_revoke(req_id,admin):
    now=_now()
    with LOCK,connect() as c:
        row=_db(c,'SELECT * FROM workspace_access_requests WHERE id=?',(req_id,)).fetchone()
        if not row:return (404,{'error':'Workspace access request not found.'})
        req=_access_request_row(row)
        if req['status']!='APPROVED' or req['revoked_at']:return (409,{'error':'Only active approved access can be revoked.'})
        _db(c,'UPDATE workspace_access_requests SET revoked_at=? WHERE id=? AND revoked_at IS NULL',(now,req_id))
        _db(c,'UPDATE workspace_access_sessions SET revoked_at=? WHERE request_id=? AND revoked_at IS NULL',(now,req_id))
        _audit_record(c,'workspace access revoked','workspace_access_request',req_id,f"Asset-management access for {req['display_name']} was revoked by the workspace owner",previous={'status':'APPROVED','permission_scope':req['permission_scope']},new={'status':'REVOKED','identity_id':req['identity_id'],'permission_scope':req['permission_scope']},actor=admin['admin_name'])
        updated=_db(c,'SELECT * FROM workspace_access_requests WHERE id=?',(req_id,)).fetchone()
    return (200,_access_request_row(updated))
def _new_access_context(admin):
    now=datetime.now(timezone.utc);sid='WAC-'+secrets.token_urlsafe(24);created=now.isoformat(timespec='seconds');expiry=(now+timedelta(seconds=ACCESS_CONTEXT_TTL)).isoformat(timespec='seconds')
    with LOCK,connect() as c:
        _db(c,'INSERT INTO workspace_access_contexts(id,created_by,created_at,expires_at,status) VALUES (?,?,?,?,?)',(sid,admin['admin_name'],created,expiry,'ACTIVE'))
        _audit_record(c,'workspace access link created','workspace_access_context',sid,'Owner created a time-limited asset-management request QR link',new={'status':'ACTIVE','expires_at':expiry,'permission_scope':ACCESS_SCOPE},actor=admin['admin_name'])
    return {'id':sid,'created_at':created,'expires_at':expiry,'status':'ACTIVE','url':_access_request_url(_valid_public_base(),sid)}
class Handler(SimpleHTTPRequestHandler):
    def __init__(self,*a,**kw): super().__init__(*a,directory=str(ROOT),**kw)
    def log_message(self,*a): pass
    def _origin_allowed(self):
        origin=self.headers.get('Origin')
        if not origin: return True
        if ALLOWED_ORIGIN and origin==ALLOWED_ORIGIN: return True
        try:
            p=urlsplit(origin); host=self.headers.get('Host','').lower()
            return bool(p.scheme in ('http','https') and p.netloc.lower()==host)
        except Exception:return False
    def _cors(self):
        origin=self.headers.get('Origin')
        if origin and origin==ALLOWED_ORIGIN:
            self.send_header('Access-Control-Allow-Origin',ALLOWED_ORIGIN)
            self.send_header('Access-Control-Allow-Credentials','true')
            self.send_header('Vary','Origin')
    def reject_disallowed_origin(self):
        if not self._origin_allowed(): self.send_json({'error':'Origin not allowed. Configure ALLOWED_ORIGIN to exactly match the deployed frontend origin.'},403); return True
        return False
    def send_json(self,data,status=200,extra_headers=None):
        b=json.dumps(data,ensure_ascii=False).encode(); self.send_response(status); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(b))); self._cors()
        for k,v in (extra_headers or []): self.send_header(k,v)
        self.end_headers(); self.wfile.write(b)
    def send_svg(self,svg):
        b=svg.encode(); self.send_response(200); self.send_header('Content-Type','image/svg+xml'); self.send_header('Cache-Control','no-store'); self.send_header('Content-Length',str(len(b))); self._cors(); self.end_headers(); self.wfile.write(b)
    def do_OPTIONS(self):
        if self.reject_disallowed_origin(): return
        self.send_response(204); self._cors(); self.send_header('Access-Control-Allow-Methods','GET, POST, DELETE, OPTIONS'); self.send_header('Access-Control-Allow-Headers','Content-Type, X-CSRF-Token, X-Request-Proof'); self.send_header('Access-Control-Max-Age','600'); self.send_header('Content-Length','0'); self.end_headers()
    def rows(self,kind):
        order='record_order' if DATABASE_URL else 'rowid'; marker='%s' if DATABASE_URL else '?'
        with LOCK,connect() as c:return [json.loads(r['body']) for r in c.execute(f'SELECT body FROM records WHERE kind={marker} ORDER BY {order}',(kind,))]
    def save(self,kind,obj):
        with LOCK,connect() as c:_store_record(c,kind,obj)
    def audit(self,action,entity,entityId,description,previous=None,new=None,actor='Workspace analyst'):
        with LOCK,connect() as c:return _audit_record(c,action,entity,entityId,description,previous,new,actor)
    def _body(self,limit=1024*1024):
        raw=self.headers.get('Content-Length')
        if raw is None: raise ValueError('Content-Length is required')
        size=int(raw)
        if size<0 or size>limit: raise OverflowError('Request body is too large')
        raw=self.rfile.read(size)
        if len(raw)!=size: raise ValueError('Incomplete request body')
        data=json.loads(raw or b'{}')
        if not isinstance(data,dict): raise ValueError('JSON body must be an object')
        return data
    def _cookie(self):
        try:return SimpleCookie(self.headers.get('Cookie','')).get(ADMIN_COOKIE).value
        except Exception:return ''
    def _access_cookie(self):
        try:return SimpleCookie(self.headers.get('Cookie','')).get(ACCESS_COOKIE).value
        except Exception:return ''
    def _access_verify_cookie(self):
        try:return SimpleCookie(self.headers.get('Cookie','')).get(ACCESS_VERIFY_COOKIE).value
        except Exception:return ''
    def _admin(self):
        return _admin_session(self._cookie(),self.headers.get('X-CSRF-Token',''))
    def _workspace_identity(self):
        admin=self._admin()
        if admin:return {'role':'owner','admin_name':admin['admin_name'],'csrf':admin['csrf'],'scope':'*','expires_at':admin['expires_at']}
        try:
            sid,token=self._access_cookie().split('.',1)
            if not re.fullmatch(r'W(?:A|P)S-[A-Fa-f0-9]{32}',sid) or not re.fullmatch(r'[A-Fa-f0-9]{64}',token):return None
            if sid.startswith('WPS-'):
                with LOCK,connect() as c:row=_db(c,'SELECT * FROM workspace_passphrase_sessions WHERE id=?',(sid,)).fetchone()
                if not row or row['revoked_at'] or _expired(row['expires_at']):return None
                if not hmac.compare_digest(row['token_hash'],hashlib.sha256(token.encode()).hexdigest()):return None
                csrf=hmac.new(DEMO_SESSION_SECRET,('workspace-csrf|'+sid+'|'+token).encode(),hashlib.sha256).hexdigest()
                if not hmac.compare_digest(row['csrf_hash'],hashlib.sha256(csrf.encode()).hexdigest()):return None
                csrf_header=self.headers.get('X-CSRF-Token','')
                if csrf_header and not hmac.compare_digest(csrf,csrf_header):return None
                return {'role':'asset-manager','identity_id':row['identity_id'],'display_name':'Passphrase user','session_id':sid,'scope':row['permission_scope'],'csrf':csrf,'expires_at':row['expires_at']}
            with LOCK,connect() as c:
                row=_db(c,'SELECT s.*,r.display_name,r.status AS request_status,r.revoked_at AS request_revoked,r.identity_id AS request_identity FROM workspace_access_sessions s JOIN workspace_access_requests r ON r.id=s.request_id WHERE s.id=?',(sid,)).fetchone()
            if not row or row['revoked_at'] or row['request_revoked'] or row['request_status']!='APPROVED' or _expired(row['expires_at']):return None
            if not hmac.compare_digest(row['token_hash'],hashlib.sha256(token.encode()).hexdigest()):return None
            csrf=hmac.new(DEMO_SESSION_SECRET,('workspace-csrf|'+sid+'|'+token).encode(),hashlib.sha256).hexdigest()
            if not hmac.compare_digest(row['csrf_hash'],hashlib.sha256(csrf.encode()).hexdigest()):return None
            csrf_header=self.headers.get('X-CSRF-Token','')
            if csrf_header and not hmac.compare_digest(csrf,csrf_header):return None
            return {'role':'asset-manager','identity_id':row['request_identity'],'display_name':row['display_name'],'request_id':row['request_id'],'session_id':sid,'scope':row['permission_scope'],'csrf':csrf,'expires_at':row['expires_at']}
        except Exception:return None
    def _require_workspace(self,mutate=False,resource=None):
        if not self._origin_allowed():self.send_json({'error':'Origin not allowed'},403);return None
        identity=self._workspace_identity()
        if not identity:self.send_json({'error':'A valid owner or approved workspace access session is required.'},401);return None
        if mutate:
            if not self.headers.get('X-CSRF-Token'):self.send_json({'error':'X-CSRF-Token is required for workspace changes.'},403);return None
            if identity['role']!='owner' and resource!='assets':self.send_json({'error':'Your approved asset-management scope does not allow this change.'},403);return None
        return identity
    def _require_admin(self,mutate=False):
        if not self._origin_allowed(): self.send_json({'error':'Origin not allowed'},403); return None
        admin=self._admin()
        if not admin: self.send_json({'error':'A valid demo administrator session and CSRF token are required.'},401); return None
        if mutate and not self.headers.get('X-CSRF-Token'):
            self.send_json({'error':'X-CSRF-Token is required for administrator actions.'},403); return None
        return admin
    def _legacy_local_write_allowed(self):
        # For the LAN presentation, only the presenter computer may use the
        # existing general-purpose mutation routes. Phones use the narrowly
        # scoped demo request endpoints above.
        if DATABASE_URL or not _demo_enabled(): return True
        try:return ipaddress.ip_address(self.client_address[0]).is_loopback
        except (ValueError,IndexError):return False
    def do_GET(self):
        if self.reject_disallowed_origin(): return
        parsed=urlsplit(self.path); path=parsed.path; query=parse_qs(parsed.query)
        if path=='/api/live':return self.send_json({'status':'live'})
        if path=='/api/ready':
            try:
                with LOCK,connect() as c:c.execute('SELECT 1').fetchone(); c.execute('SELECT version FROM schema_migrations').fetchone()
                return self.send_json({'status':'ready','database':'available'})
            except Exception:return self.send_json({'status':'unavailable','database':'unavailable'},503)
        if path=='/api/access/config':return self.send_json({'enabled':_workspace_access_enabled(),'passphraseRequired':True,'permissionScope':ACCESS_SCOPE,'requestTtlSeconds':DEMO_REQUEST_TTL})
        if path=='/api/access/passphrase':return self.send_json({'verified':_access_verification_valid(self._access_verify_cookie())})
        if path=='/api/access/session':
            identity=self._workspace_identity()
            if not identity:return self.send_json({'error':'No active workspace session.'},401)
            return self.send_json({'role':identity['role'],'identityId':identity.get('identity_id'),'displayName':identity.get('display_name') or identity.get('admin_name'),'permissionScope':identity['scope'],'expiresAt':identity['expires_at'],'csrfToken':identity['csrf']})
        access_status=re.fullmatch(r'/api/access/requests/(WAR-[A-Fa-f0-9]{32})',path)
        if access_status:
            if not _rate_allowed(self.client_address[0],'workspace-access-status',50,60):return self.send_json({'error':'Access request status polling limit reached.'},429)
            key=self.headers.get('X-Request-Proof','')
            if not re.fullmatch(r'[A-Fa-f0-9-]{32,36}',key):return self.send_json({'error':'Private request proof is required.'},403)
            with LOCK,connect() as c:
                row=_db(c,'SELECT * FROM workspace_access_requests WHERE id=?',(access_status.group(1),)).fetchone()
                if not row:return self.send_json({'error':'Access request not found.'},404)
                if not hmac.compare_digest(row['proof_hash'],_access_proof_hash(key)):return self.send_json({'error':'This request belongs to another browser session.'},403)
                result=_access_request_row(_expire_workspace_request(c,row))
            return self.send_json(result)
        if path.startswith('/api/access/admin/'):
            admin=self._require_admin()
            if not admin:return
            if path=='/api/access/admin/requests':
                with LOCK,connect() as c:
                    rows=_db(c,'SELECT * FROM workspace_access_requests ORDER BY created_at DESC LIMIT 100',()).fetchall()
                    result=[_access_request_row(_expire_workspace_request(c,row)) for row in rows]
                return self.send_json({'requests':result})
            if path=='/api/access/admin/security-events':return self.send_json({'events':_security_event_rows()})
            if path=='/api/access/admin/qr':
                context_id=(query.get('contextId') or [''])[0];base=_valid_public_base()
                if not base:return self.send_json({'error':'Set DEMO_PUBLIC_BASE_URL to a reachable HTTPS URL or private Wi-Fi IP before creating an access QR code.'},503)
                with LOCK,connect() as c:row=_db(c,"SELECT * FROM workspace_access_contexts WHERE id=? AND created_by=? AND status='ACTIVE'",(context_id,admin['admin_name'])).fetchone()
                if not row or _expired(row['expires_at']):return self.send_json({'error':'Access link is closed or expired.'},410)
                url=_access_request_url(base,context_id)
                try:
                    import qrcode
                    from qrcode.image.svg import SvgPathImage
                    qr=qrcode.QRCode(box_size=7,border=3);qr.add_data(url);qr.make(fit=True);stream=io.BytesIO();qr.make_image(image_factory=SvgPathImage).save(stream);svg=stream.getvalue().decode()
                except ImportError:return self.send_json({'error':'QR support is unavailable. Install requirements.txt and restart the API.'},503)
                return self.send_json({'url':url,'svg':svg,'expires_at':row['expires_at']})
            return self.send_json({'error':'Unknown workspace access admin route.'},404)
        if path.startswith('/api/access/requests/') and path.endswith('/establish') and self.command=='GET':return self.send_json({'error':'Use POST to establish an approved session.'},405)
        if path.startswith('/api/access/requests/') and path.endswith('/establish'):return self.send_json({'error':'Use POST to establish an approved session.'},405)
        if path=='/api/demo/config':return self.send_json({'enabled':_demo_enabled(),'publicBaseConfigured':bool(_valid_public_base()),'adminName':DEMO_ADMIN_NAME if _demo_enabled() else None})
        if path=='/api/demo/requests' or re.fullmatch(r'/api/demo/requests/DRQ-[A-Fa-f0-9]{32}',path):
            if not _demo_enabled():return self.send_json({'error':'Live demo approval is not configured.'},503)
            if path.endswith('/requests'):
                return self.send_json({'error':'Use POST to create a demo request.'},405)
            if not _rate_allowed(self.client_address[0],'public-status',40,60):return self.send_json({'error':'Status polling rate limit reached.'},429)
            req=_expire_request_by_id(path.rsplit('/',1)[-1])
            if not req:return self.send_json({'error':'Demo request not found.'},404)
            return self.send_json(req)
        if path.startswith('/api/demo/admin/'):
            if path=='/api/demo/admin/session' and self.command=='GET':
                admin=self._require_admin()
                if not admin:return
                active=None
                with LOCK,connect() as c:
                    row=_db(c,"SELECT * FROM demo_sessions WHERE created_by=? ORDER BY created_at DESC LIMIT 1",(admin['admin_name'],)).fetchone(); row=_expire_session(c,row)
                    if row:active={'id':row['id'],'created_at':row['created_at'],'expires_at':row['expires_at'],'status':row['status']}
                return self.send_json({'adminName':admin['admin_name'],'expiresAt':admin['expires_at'],'session':active})
            admin=self._require_admin()
            if not admin:return
            if path=='/api/demo/admin/requests':
                sid=(query.get('sessionId') or [''])[0]
                with LOCK,connect() as c:
                    session=_db(c,'SELECT * FROM demo_sessions WHERE id=? AND created_by=?',(sid,admin['admin_name'])).fetchone()
                    if not session:return self.send_json({'error':'Demo session not found.'},404)
                    session=_expire_session(c,session)
                    rows=_db(c,'SELECT * FROM demo_login_requests WHERE session_id=? ORDER BY created_at DESC',(sid,)).fetchall()
                    result=[_status_row(_expire_request(c,r)) for r in rows]
                return self.send_json({'requests':result,'sessionStatus':session['status'],'sessionExpiresAt':session['expires_at']})
            if path=='/api/demo/admin/qr':
                sid=(query.get('sessionId') or [''])[0]; base=_valid_public_base()
                if not base:return self.send_json({'error':'Set DEMO_PUBLIC_BASE_URL to a reachable HTTPS URL, or for local Wi-Fi use http://<private-LAN-IP>:<port>.'},503)
                with LOCK,connect() as c:
                    row=_db(c,"SELECT * FROM demo_sessions WHERE id=? AND created_by=? AND status='ACTIVE'",(sid,admin['admin_name'])).fetchone(); row=_expire_session(c,row)
                if not row or row['status']!='ACTIVE':return self.send_json({'error':'Demo session is closed or expired.'},410)
                url=_demo_login_url(base,sid)
                try:
                    import qrcode
                    from qrcode.image.svg import SvgPathImage
                    qr=qrcode.QRCode(box_size=7,border=3); qr.add_data(url); qr.make(fit=True); stream=io.BytesIO(); qr.make_image(image_factory=SvgPathImage).save(stream); svg=stream.getvalue().decode()
                except ImportError:return self.send_json({'error':'QR support is unavailable. Install requirements.txt and restart the API.'},503)
                return self.send_json({'url':url,'svg':svg})
            return self.send_json({'error':'Unknown demo admin route.'},404)
        if path.startswith('/api/'):
            k=path[5:]
            if k not in TABLES:return self.send_json({'error':'Unknown resource'},404)
            if not self._require_workspace():return
            try:return self.send_json(self.rows(k))
            except Exception:return self.send_json({'error':'Database unavailable'},503)
        if path in ('/','/demo-login','/demo-login/','/access-request','/access-request/'):
            self.path='/index.html'+(('?'+parsed.query) if parsed.query else '')
        return super().do_GET()
    def do_POST(self):
        if self.reject_disallowed_origin(): return
        path=urlsplit(self.path).path
        limit=4096 if path.startswith('/api/demo/') or path.startswith('/api/access/') else 1024*1024
        try:d=self._body(limit)
        except OverflowError:return self.send_json({'error':'Request body exceeds the allowed size.'},413)
        except Exception:return self.send_json({'error':'Invalid JSON body or Content-Length.'},400)
        parts=path.strip('/').split('/')
        if path=='/api/access/requests':
            if not _access_verification_valid(self._access_verify_cookie()):return self.send_json({'error':'Enter the workspace access passphrase before submitting an owner access request.'},403)
            context_id=d.get('context_id','')
            if not isinstance(context_id,str) or (context_id and not re.fullmatch(r'WAC-[A-Za-z0-9_-]{20,40}',context_id)):return self.send_json({'error':'Invalid access link context.'},400)
            status,result=_create_workspace_access_request(d.get('display_name'),d.get('request_key'),context_id,self.client_address[0]);return self.send_json(result,status)
        if path=='/api/access/logout':
            identity=self._require_workspace(mutate=True)
            if not identity:return
            if identity['role']=='owner':return self.send_json({'error':'Use the owner sign-out action.'},400)
            if not _rate_allowed(self.client_address[0],'workspace-access-logout',20,60):return self.send_json({'error':'Too many sign-out attempts.'},429)
            with LOCK,connect() as c:
                if identity['session_id'].startswith('WPS-'):_db(c,'UPDATE workspace_passphrase_sessions SET revoked_at=? WHERE id=? AND revoked_at IS NULL',(_now(),identity['session_id']))
                else:_db(c,'UPDATE workspace_access_sessions SET revoked_at=? WHERE id=? AND revoked_at IS NULL',(_now(),identity['session_id']))
                _audit_record(c,'workspace session ended','workspace_access_session',identity['session_id'],f"{identity['display_name']} ended an asset-management session",previous={'status':'ACTIVE','permission_scope':identity['scope']},new={'status':'ENDED','result':'success'},actor=identity['display_name'])
            same='None' if ALLOWED_ORIGIN.startswith('https://') else 'Strict';secure='; Secure' if ALLOWED_ORIGIN.startswith('https://') else ''
            return self.send_json({'ok':True},200,[('Set-Cookie',f'{ACCESS_COOKIE}=; Path=/; HttpOnly; SameSite={same}; Max-Age=0'+secure)])
        match=re.fullmatch(r'/api/access/requests/(WAR-[A-Fa-f0-9]{32})/establish',path)
        if match:
            if not self._origin_allowed():return self.send_json({'error':'Origin not allowed.'},403)
            if not _access_verification_valid(self._access_verify_cookie()):return self.send_json({'error':'Re-enter the workspace access passphrase before establishing the approved session.'},403)
            if not _rate_allowed(self.client_address[0],'workspace-access-establish',20,60):return self.send_json({'error':'Too many session-establishment attempts. Please wait and retry.'},429)
            status,result,headers=_establish_workspace_access(match.group(1),self.headers.get('X-Request-Proof',''))
            return self.send_json(result,status,headers)
        if path=='/api/access/passphrase':
            status,result,headers=_verify_workspace_passphrase(d.get('passphrase'),self.client_address[0])
            if status!=200:return self.send_json(result,status)
            expiry=int(time.time())+ACCESS_VERIFY_TTL;ticket=_access_verification_cookie(expiry);secure='; Secure' if ALLOWED_ORIGIN.startswith('https://') else '';same='None' if ALLOWED_ORIGIN.startswith('https://') else 'Strict'
            headers=(headers or [])+[('Set-Cookie',f'{ACCESS_VERIFY_COOKIE}={ticket}; Path=/api/access; HttpOnly; SameSite={same}; Max-Age={ACCESS_VERIFY_TTL}'+secure)]
            return self.send_json(result,status,headers)
        if path.startswith('/api/access/admin/'):
            admin=self._require_admin(mutate=True)
            if not admin:return
            if not _rate_allowed(self.client_address[0],'workspace-access-owner-write',120,60):return self.send_json({'error':'Too many workspace access changes. Please wait before trying again.'},429)
            if path=='/api/access/admin/contexts':
                base=_valid_public_base()
                if not base:return self.send_json({'error':'Configure DEMO_PUBLIC_BASE_URL before creating an access QR link.'},503)
                result=_new_access_context(admin);return self.send_json(result,201)
            match=re.fullmatch(r'/api/access/admin/requests/(WAR-[A-Fa-f0-9]{32})/decision',path)
            if match:
                status,result=_decide_workspace_access(match.group(1),d.get('decision'),admin);return self.send_json(result,status)
            match=re.fullmatch(r'/api/access/admin/requests/(WAR-[A-Fa-f0-9]{32})/revoke',path)
            if match:
                status,result=_decide_workspace_revoke(match.group(1),admin);return self.send_json(result,status)
            return self.send_json({'error':'Unknown workspace access admin route.'},404)
        if path=='/api/demo/admin/login':
            if not _demo_enabled():return self.send_json({'error':'Set a 20+ character DEMO_ADMIN_PASSWORD and 32+ byte DEMO_SESSION_SECRET on the API host.'},503)
            if not self._rate_allowed_login():return
            supplied=d.get('password')
            if not isinstance(supplied,str) or not hmac.compare_digest(supplied,DEMO_ADMIN_PASSWORD):return self.send_json({'error':'Invalid administrator passphrase.'},401)
            sid,csrf,exp,expiry=_create_admin_session(DEMO_ADMIN_NAME); token=_cookie_make(sid,csrf,exp)
            secure=bool(ALLOWED_ORIGIN.startswith('https://')); same='None' if secure else 'Strict'
            cookie=f'{ADMIN_COOKIE}={token}; Path=/; HttpOnly; SameSite={same}; Max-Age={DEMO_SESSION_TTL}'+('; Secure' if secure else '')
            return self.send_json({'adminName':DEMO_ADMIN_NAME,'csrfToken':csrf,'expiresAt':expiry},200,[('Set-Cookie',cookie)])
        if path.startswith('/api/demo/admin/'):
            admin=self._require_admin(mutate=True)
            if not admin:return
            if path=='/api/demo/admin/logout':
                with LOCK,connect() as c:_db(c,'UPDATE demo_admin_sessions SET revoked_at=? WHERE id=?',( _now(),admin['id']))
                return self.send_json({'ok':True},200,[('Set-Cookie',f'{ADMIN_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0')])
            if path=='/api/demo/admin/sessions':
                base=_valid_public_base()
                if not base:return self.send_json({'error':'Configure DEMO_PUBLIC_BASE_URL before starting a live session.'},503)
                now=_now(); sid=secrets.token_urlsafe(24); expiry=(datetime.now(timezone.utc)+timedelta(seconds=DEMO_SESSION_TTL)).isoformat(timespec='seconds')
                with LOCK,connect() as c:
                    old=_db(c,"SELECT * FROM demo_sessions WHERE created_by=? AND status='ACTIVE'",(admin['admin_name'],)).fetchall()
                    for previous in old:
                        _expire_session(c,previous); _db(c,"UPDATE demo_sessions SET status='CLOSED' WHERE id=? AND status='ACTIVE'",(previous['id'],))
                        _expire_pending_for_session(c,previous['id'],'the presenter closed its session')
                    _db(c,'INSERT INTO demo_sessions(id,created_by,created_at,expires_at,status) VALUES (?,?,?,?,?)',(sid,admin['admin_name'],now,expiry,'ACTIVE'))
                    _audit_record(c,'demo session started','demo_session',sid,'QR live demo session started',new={'status':'ACTIVE','expires_at':expiry},actor=admin['admin_name'])
                return self.send_json({'id':sid,'status':'ACTIVE','expires_at':expiry,'loginUrl':_demo_login_url(base,sid) },201)
            match=re.fullmatch(r'/api/demo/admin/requests/(DRQ-[A-Fa-f0-9]{32})/decision',path)
            if match:
                status,result=_decide_demo_request(match.group(1),d.get('decision'),admin);return self.send_json(result,status)
            match=re.fullmatch(r'/api/demo/admin/sessions/([A-Za-z0-9_-]+)/reset',path)
            if match:
                status,result=_reset_demo_session(match.group(1),admin);return self.send_json(result,status)
            return self.send_json({'error':'Unknown demo admin route.'},404)
        if path=='/api/demo/requests':
            if not _demo_enabled():return self.send_json({'error':'Live demo approval is not configured.'},503)
            status,result=_create_demo_request(str(d.get('session_id','')),d.get('display_name'),d.get('idempotency_key'),self.client_address[0]);return self.send_json(result,status)
        if parts[0]!='api':return self.send_json({'error':'Unknown route'},404)
        if len(parts)==2 and parts[1]=='reset':
            if not self._require_workspace(mutate=True,resource='reset'):return
            if self._workspace_identity()['role']!='owner':return self.send_json({'error':'Only the workspace owner may reset records.'},403)
            with LOCK,connect() as c:c.execute('DELETE FROM records')
            seed(); self.audit('demo reset','workspace','workspace','Demo workspace reset to fictional seed data'); return self.send_json({'ok':True})
        k=parts[1] if len(parts)>1 else ''
        if k not in TABLES:return self.send_json({'error':'Unknown resource'},404)
        identity=self._require_workspace(mutate=True,resource=k)
        if not identity:return
        if not d.get('id'):return self.send_json({'error':'Record id is required'},400)
        existing=next((x for x in self.rows(k) if x['id']==d['id']),None)
        action=d.pop('_action','updated' if existing else 'created'); description=d.pop('_description',f"{k.rstrip('s').title()} {d['id']} saved")
        self.save(k,d)
        if k!='audit':self.audit(action,k.rstrip('s'),d['id'],description,existing,d,identity.get('display_name') or identity.get('admin_name') or 'Workspace owner')
        return self.send_json(d,201 if not existing else 200)
    def _rate_allowed_login(self):
        if not _rate_allowed(self.client_address[0],'admin-login',5,900):self.send_json({'error':'Too many administrator login attempts. Try again later.'},429); return False
        return True
    def do_DELETE(self):
        if self.reject_disallowed_origin():return
        p=urlsplit(self.path).path.strip('/').split('/')
        if len(p)!=3 or p[0]!='api' or p[1] not in TABLES:return self.send_json({'error':'Unknown route'},404)
        kind,rid=p[1],p[2]
        identity=self._require_workspace(mutate=True,resource=kind)
        if not identity:return
        old=next((x for x in self.rows(kind) if x['id']==rid),None)
        if not old:return self.send_json({'error':'Record not found'},404)
        if kind=='assets' and any(x.get('assetId')==rid for x in self.rows('findings')+self.rows('events')):return self.send_json({'error':'Asset has linked findings or events and cannot be deleted.'},409)
        marker='%s' if DATABASE_URL else '?'
        with LOCK,connect() as c:c.execute(f'DELETE FROM records WHERE kind={marker} AND id={marker}',(kind,rid))
        self.audit('deleted',kind.rstrip('s'),rid,f"{kind.rstrip('s').title()} {rid} deleted",old,None,identity.get('display_name') or identity.get('admin_name') or 'Workspace owner');return self.send_json({'ok':True})

if __name__=='__main__':
    migrate(); seed(); port=int(os.environ.get('PORT','8080')); host=os.environ.get('HOST','0.0.0.0')
    print(f'CyberRakshak AI listening on {host}:{port} (simulation only)',flush=True)
    ThreadingHTTPServer((host,port),Handler).serve_forever()
