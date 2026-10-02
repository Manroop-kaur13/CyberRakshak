"""CyberRakshak AI local demo server. All security actions are simulated."""
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import json, sqlite3, os, threading

ROOT = Path(__file__).parent
DB = ROOT / 'cyberrakshak.sqlite3'
LOCK = threading.RLock()
TABLES = ('assets','findings','events','correlations','investigations','remediations','audit','settings')

def connect():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
    c.execute('CREATE TABLE IF NOT EXISTS records (kind TEXT NOT NULL, id TEXT NOT NULL, body TEXT NOT NULL, PRIMARY KEY(kind,id))')
    return c

def seed():
    with LOCK, connect() as c:
        if c.execute('SELECT count(*) FROM records').fetchone()[0]: return
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
            for x in rows:c.execute('INSERT INTO records VALUES (?,?,?)',(k,x['id'],json.dumps(x)))

class Handler(SimpleHTTPRequestHandler):
    def __init__(self,*a,**kw): super().__init__(*a,directory=str(ROOT),**kw)
    def log_message(self,*a): pass
    def send_json(self,data,status=200):
        b=json.dumps(data).encode(); self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(b))); self.send_header('Access-Control-Allow-Origin','*'); self.end_headers(); self.wfile.write(b)
    def rows(self,kind):
        with LOCK,connect() as c:return [json.loads(r['body']) for r in c.execute('SELECT body FROM records WHERE kind=? ORDER BY rowid',(kind,))]
    def save(self,kind,obj):
        with LOCK,connect() as c:c.execute('INSERT OR REPLACE INTO records VALUES (?,?,?)',(kind,obj['id'],json.dumps(obj)))
    def audit(self,action,entity,entityId,description,previous=None,new=None,actor='Workspace analyst'):
        import datetime
        a={'id':'AUD-'+str(__import__('time').time_ns()),'time':datetime.datetime.now().astimezone().isoformat(timespec='seconds'),'actor':actor,'action':action,'entityType':entity,'entityId':entityId,'description':description,'previous':previous,'new':new,'origin':'User'}; self.save('audit',a)
    def do_GET(self):
        if self.path=='/api/live':return self.send_json({'status':'live'})
        if self.path=='/api/ready':
            try:
                with LOCK,connect() as c:c.execute('SELECT 1').fetchone()
                return self.send_json({'status':'ready','database':'available'})
            except Exception:return self.send_json({'status':'unavailable','database':'unavailable'},503)
        if self.path.startswith('/api/'):
            k=self.path[5:].split('?')[0]
            if k not in TABLES:return self.send_json({'error':'Unknown resource'},404)
            try:return self.send_json(self.rows(k))
            except Exception:return self.send_json({'error':'Database unavailable'},503)
        if self.path=='/':self.path='/index.html'
        return super().do_GET()
    def do_POST(self):
        try:d=json.loads(self.rfile.read(int(self.headers.get('Content-Length',0)))); path=self.path.strip('/').split('/')
        except Exception:return self.send_json({'error':'Invalid JSON body'},400)
        if not isinstance(d,dict):return self.send_json({'error':'JSON body must be an object'},400)
        if path[0]!='api':return self.send_json({'error':'Unknown route'},404)
        if path[1]=='reset':
            with LOCK,connect() as c:c.execute('DELETE FROM records')
            seed(); self.audit('demo reset','workspace','workspace','Demo workspace reset to fictional seed data'); return self.send_json({'ok':True})
        k=path[1]
        if k not in TABLES:return self.send_json({'error':'Unknown resource'},404)
        if not d.get('id'):return self.send_json({'error':'Record id is required'},400)
        existing=next((x for x in self.rows(k) if x['id']==d['id']),None)
        action=d.pop('_action','updated' if existing else 'created')
        description=d.pop('_description',f"{k.rstrip('s').title()} {d['id']} saved")
        self.save(k,d)
        if k!='audit':self.audit(action,k.rstrip('s'),d['id'],description,existing,d)
        return self.send_json(d,201 if not existing else 200)
    def do_DELETE(self):
        p=self.path.strip('/').split('/')
        if len(p)!=3 or p[0]!='api' or p[1] not in TABLES:return self.send_json({'error':'Unknown route'},404)
        kind,rid=p[1],p[2]; old=next((x for x in self.rows(kind) if x['id']==rid),None)
        if not old:return self.send_json({'error':'Record not found'},404)
        if kind=='assets' and any(x.get('assetId')==rid for x in self.rows('findings')+self.rows('events')):return self.send_json({'error':'Asset has linked findings or events and cannot be deleted.'},409)
        with LOCK,connect() as c:c.execute('DELETE FROM records WHERE kind=? AND id=?',(kind,rid))
        self.audit('deleted',kind.rstrip('s'),rid,f"{kind.rstrip('s').title()} {rid} deleted",old,None); return self.send_json({'ok':True})

if __name__=='__main__':
    seed(); port=int(os.environ.get('PORT','8080')); host=os.environ.get('HOST','0.0.0.0')
    print(f'CyberRakshak AI listening on {host}:{port} (simulation only)',flush=True)
    ThreadingHTTPServer((host,port),Handler).serve_forever()
