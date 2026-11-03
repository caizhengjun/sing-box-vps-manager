import asyncio
import base64
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
LIB=Path(__file__).resolve().parents[1]/'lib'
sys.path.insert(0,str(LIB))
try:
 import subscription as sub
 from aiohttp import web
 from aiohttp.test_utils import TestClient,TestServer
except ImportError:sub=None

@unittest.skipIf(sub is None,'aiohttp test dependency unavailable')
class SubscriptionTest(unittest.IsolatedAsyncioTestCase):
 async def asyncSetUp(self):
  self.t=tempfile.TemporaryDirectory();sub.PUBLIC=Path(self.t.name)/'pub.json'
  token='T'*48
  sub.PUBLIC.write_text(json.dumps([{'token_hash':hashlib.sha256(token.encode()).hexdigest(),'name':'张三',
    'started':100,'expires':200,'upload':10,'download':20,'quota':1000,'outs':[]}]))
  app=web.Application();app.router.add_get('/sub/{token}',sub.handle,allow_head=True)
  app.router.add_get('/admin/{token}',sub.handle,allow_head=True)
  self.client=TestClient(TestServer(app));await self.client.start_server()
 async def asyncTearDown(self):await self.client.close();self.t.cleanup()
 async def test_headers_and_secrecy(self):
  r=await self.client.get('/sub/'+('T'*48)+'?format=singbox')
  self.assertEqual(r.status,403)
  self.assertEqual(r.headers['Subscription-Userinfo'],'upload=10; download=20; total=1000; expire=200')
  self.assertEqual(r.headers['X-Subscription-Start'],'100')
  self.assertEqual(base64.b64decode(r.headers['Profile-Title']).decode(),'张三')
  self.assertEqual((await self.client.get('/sub/'+('X'*48))).status,404)
  self.assertEqual((await self.client.head('/sub/'+('T'*48))).status,403)
  self.assertEqual((await self.client.get('/admin/'+('T'*48))).status,404)
