"""Console security regression tests. Install console/requirements.txt to run HTTP cases."""
import importlib.util
import json
import sqlite3
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

CONSOLE=Path(__file__).resolve().parents[1]/'console'
sys.path.insert(0,str(CONSOLE))
import broker

class BrokerTests(unittest.TestCase):
 def test_new_node_inherits_public_settings_from_local_node(self):
  with tempfile.TemporaryDirectory() as tmp:
   db=Path(tmp)/'manager.sqlite'
   with sqlite3.connect(db) as d:
    d.execute('CREATE TABLE nodes(mode TEXT,state TEXT,sni TEXT,tags TEXT)')
    d.execute('INSERT INTO nodes VALUES(?,?,?,?)',('local','active','addons.mozilla.org','["美国","测试"]'))
   with mock.patch.object(broker.ctl,'DB',db):
    self.assertEqual(broker.primary_node_defaults('korea.tongnan.shop'),('addons.mozilla.org',['测试','韩国']))
 def test_private_and_loopback_ips_rejected(self):
  for ip in ('127.0.0.1','10.1.2.3','169.254.169.254','::1'):
   with self.assertRaises(broker.Error):broker.public_host(ip)
  self.assertEqual(broker.public_host('1.1.1.1'),'1.1.1.1')
 def test_unknown_operation_rejected(self):
  with self.assertRaises(broker.Error):broker.dispatch({'op':'submit','kind':'shell','params':{'command':'whoami'}})
 def test_invalid_node_ids_rejected(self):
  d=sqlite3.connect(':memory:')
  try:
   d.execute('CREATE TABLE nodes(id TEXT,state TEXT)')
   d.execute('INSERT INTO nodes VALUES("good","active")')
   self.assertEqual(broker.validate_node_ids(d,['good','good']),['good'])
   for value in ('good',['bad'],[1]):
    with self.assertRaises(broker.Error):broker.validate_node_ids(d,value)
  finally:d.close()
 def test_no_password_or_task_parameters_persisted(self):
  with tempfile.TemporaryDirectory() as tmp,mock.patch.object(broker,'BASE',Path(tmp)),mock.patch.object(broker,'JOBS') as jobs:
   jobs.full.return_value=False
   result=broker.dispatch({'op':'submit','kind':'node.initialise','actor':'admin',
                          'params':{'password':'NEVER-PERSIST','confirm_fingerprint':True}})
   with broker.database() as d:
    rows=[dict(r) for r in d.execute('SELECT * FROM tasks')]
   self.assertEqual(rows[0]['id'],result['task_id'])
   self.assertNotIn('NEVER-PERSIST',json.dumps(rows))
   self.assertNotIn(b'NEVER-PERSIST',(Path(tmp)/'tasks.sqlite').read_bytes())

try:
 import app as console_app
 import pyotp
 from fastapi.testclient import TestClient
except ImportError:
 console_app=None

@unittest.skipIf(console_app is None,'console HTTP test dependencies unavailable')
class HttpSecurityTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.patch=mock.patch.object(console_app,'BASE',Path(self.tmp.name));self.patch.start();self.addCleanup(self.patch.stop)
  self.origin=mock.patch.object(console_app,'ORIGIN','https://console.example.com');self.origin.start();self.addCleanup(self.origin.stop)
  self.identity=mock.patch.object(console_app,'identity',return_value='admin@example.com');self.identity.start();self.addCleanup(self.identity.stop)
  self.client=TestClient(console_app.app,base_url='https://console.example.com')
 def test_unauthenticated_management_denied(self):
  self.assertEqual(self.client.get('/api/data').status_code,401)
 def test_foreign_origin_denied(self):
  self.assertEqual(self.client.post('/api/auth/login',json={},headers={'origin':'https://evil.example'}).status_code,403)
 def test_missing_access_configuration_fails_closed(self):
  self.identity.stop()
  with mock.patch.object(console_app,'TEAM',''):
   self.assertEqual(self.client.get('/').status_code,503)
  self.identity.start()
 def test_password_totp_csrf_and_replay(self):
  secret=pyotp.random_base32();password='test-secure-password-12345'
  with console_app.db() as d:
   d.execute('INSERT INTO admin(id,password,totp) VALUES(1,?,?)',(console_app.PASSWORD.hash(password),secret))
  headers={'origin':'https://console.example.com'}
  payload={'password':password,'code':pyotp.TOTP(secret).now()}
  r=self.client.post('/api/auth/login',json=payload,headers=headers)
  self.assertEqual(r.status_code,200)
  self.assertIn('HttpOnly',r.headers['set-cookie']);self.assertIn('Secure',r.headers['set-cookie'])
  self.assertEqual(self.client.post('/api/auth/login',json=payload,headers=headers).status_code,401)
  self.assertEqual(self.client.post('/api/auth/logout',json={},headers=headers).status_code,403)
  headers['x-csrf-token']=r.json()['csrf']
  self.assertEqual(self.client.post('/api/auth/logout',json={},headers=headers).status_code,200)
  self.assertEqual(self.client.get('/api/data').status_code,401)

if __name__=='__main__':unittest.main()
