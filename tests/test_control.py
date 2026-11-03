import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

LIB=Path(__file__).resolve().parents[1]/'lib'
sys.path.insert(0,str(LIB))
import controller as ctl
import common
import formats
import node as node_worker

class ControlTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  ctl.HOME=Path(self.tmp.name)/'private';ctl.DB=ctl.HOME/'manager.sqlite'
  ctl.PUBLIC_DIR=Path(self.tmp.name)/'public'
  self.db=ctl.database();self.addCleanup(self.db.close)
  with self.db:self.db.execute("INSERT INTO meta VALUES('subscription_domain','sub.example.com')")
  p='a'*32;u='b'*32;c='c'*32;n='d'*32
  self.pid,self.uid,self.cid,self.nid=p,u,c,n
  with self.db:
   self.db.execute('INSERT INTO plans VALUES(?,?,?,?,?,?)',(p,'标准',json.dumps(['香港','高级']),10**9,30,'¥20'))
   self.db.execute('INSERT INTO users(id,name,plan_id,token,state,cycle,started,expires,quota) VALUES(?,?,?,?,?,?,?,?,?)',
                   (u,'测试用户',p,'tok'*20,'active',c,100,common.now()+10000,10**9))
   self.db.execute('INSERT INTO nodes(id,name,domain,host,ssh_port,ssh_user,ssh_key,mode,sni,tags,state,status,stats_ready) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (n,'港一','hk.example.com','local',22,'root','','local','www.microsoft.com',json.dumps(['香港','基础']),'active','待同步',1))
 def test_any_tag_and_publish_only_applied(self):
  n=ctl.node(self.db,self.nid)
  self.assertEqual(len(ctl.effective(self.db,n)),1)
  ctl.publish(self.db)
  self.assertEqual(json.loads((ctl.PUBLIC_DIR/'published.json').read_text())[0]['outs'],[])
  with self.db:self.db.execute('UPDATE nodes SET tags=? WHERE id=?',(json.dumps(['美国']),self.nid))
  self.assertEqual(ctl.effective(self.db,ctl.node(self.db,self.nid)),[])
 def test_traffic_and_quota(self):
  n=ctl.node(self.db,self.nid);p='m_'+self.uid+'_'+self.cid
  res={'epoch':'e1','sample_at':111,'totals':{p:{'up':123,'down':321}}}
  ctl.accept_stats(self.db,n,res)
  ctl.accept_stats(self.db,ctl.node(self.db,self.nid),res)
  u=ctl.user(self.db,self.uid)
  self.assertEqual((u['upload'],u['download']),(123,321))
  res['totals'][p]={'up':500000000,'down':600000000}
  ctl.accept_stats(self.db,ctl.node(self.db,self.nid),res)
  self.assertEqual(ctl.effective(self.db,ctl.node(self.db,self.nid)),[])
 def test_disabled_and_delete_pending(self):
  with self.db:self.db.execute("UPDATE nodes SET state='deleting' WHERE id=?",(self.nid,))
  self.assertEqual(ctl.effective(self.db,ctl.node(self.db,self.nid)),[])
  with mock.patch.object(ctl,'rpc',side_effect=common.Error('offline')):
   ctl.reconcile(self.db)
  self.assertEqual(ctl.node(self.db,self.nid)['state'],'deleting')
  self.assertIn('待处理',ctl.node(self.db,self.nid)['status'])
 def test_subscription_userinfo_without_exposing_token(self):
  ctl.publish(self.db)
  raw=(ctl.PUBLIC_DIR/'published.json').read_text()
  self.assertNotIn('tok'*20,raw)
  self.assertIn('token_hash',raw)
 def test_ss2022_user_key_and_unmanaged_exclusion(self):
  c={'inbounds':[{'type':'shadowsocks','tag':'ss-legacy','listen_port':8388,'method':'2022-blake3-aes-256-gcm','password':'A'*44},
                 {'type':'shadowsocks','tag':'shadowsocks','listen_port':8389,'method':'2022-blake3-aes-256-gcm','password':'B'*44}]}
  o=formats.outbounds(c,'hk.example.com','港一','测试用户','m_'+self.uid+'_'+self.cid,{'ss':'C'*44})
  self.assertEqual(len(o),1)
  self.assertEqual(o[0]['password'],'B'*44+':'+'C'*44)
 def test_admin_is_unlimited_and_names_are_client_friendly(self):
  with self.db:
   self.db.execute('UPDATE users SET is_admin=1,expires=0,quota=0 WHERE id=?',(self.uid,))
   self.db.execute('UPDATE nodes SET name=? WHERE id=?',('🇺🇸 US-LA',self.nid))
  self.assertEqual(len(ctl.effective(self.db,ctl.node(self.db,self.nid))),1)
  with self.db:self.db.execute('UPDATE nodes SET revision=? WHERE id=?',(ctl.revision(self.db,ctl.node(self.db,self.nid)),self.nid))
  with self.db:self.db.execute('INSERT INTO grants VALUES(?,?,?)',(self.nid,'m_'+self.uid+'_'+self.cid,json.dumps([{'type':'trojan','tag':'🇺🇸 US-LA · Trojan'}])))
  ctl.publish(self.db)
  row=json.loads((ctl.PUBLIC_DIR/'published.json').read_text())[0]
  self.assertEqual((row['quota'],row['expires']),(0,0))
  self.assertTrue(row['is_admin'])
  self.assertEqual(row['outs'][0]['tag'],'🇺🇸 US-LA · Trojan')
 def test_singbox_portable_profile_omits_naive(self):
  outs=[{'type':'naive','tag':'Naive','server':'x','server_port':1},
        {'type':'trojan','tag':'Trojan','server':'x','server_port':2,'password':'p','tls':{'enabled':True,'server_name':'x'}}]
  body,_=formats.render(outs,'singbox');cfg=json.loads(body)
  self.assertEqual([o['type'] for o in cfg['outbounds'][1:]],['trojan'])
 def test_node_rename_invalidates_revision(self):
  with self.db:self.db.execute('UPDATE nodes SET revision=? WHERE id=?',('old',self.nid))
  answers=iter(['🇺🇸 US-LA','香港,基础'])
  with mock.patch.object(ctl,'ask',side_effect=lambda *a,**k:next(answers)),mock.patch.object(ctl,'reconcile'):
   ctl.edit_node(self.db,ctl.node(self.db,self.nid))
  self.assertIsNone(ctl.node(self.db,self.nid)['revision'])
 def test_client_profiles_split_compatibility_and_full(self):
  outs=[{'type':kind,'tag':kind} for kind in ('vless','trojan','hysteria2','tuic','shadowsocks','anytls','naive')]
  portable=json.loads(formats.render(outs,'singbox')[0])
  full=json.loads(formats.render(outs,'karing')[0])
  self.assertEqual([o['type'] for o in portable['outbounds'][1:]],['vless','trojan','hysteria2','tuic','shadowsocks'])
  self.assertEqual(full['outbounds'][1:],outs)
  self.assertEqual(full['outbounds'][0]['outbounds'],[o['tag'] for o in outs])
 def test_human_readable_user_details_and_assigned_node(self):
  self.assertEqual(ctl.human_bytes(341944499),'326.10 MB')
  self.assertEqual(ctl.human_bytes(2*1024**3),'2.00 GB')
  self.assertEqual(ctl.human_time(0),'永久')
  principal='m_'+self.uid+'_'+self.cid
  with self.db:self.db.execute('INSERT INTO grants VALUES(?,?,?)',(self.nid,principal,json.dumps([
      {'type':'trojan'},{'type':'hysteria2'}])))
  nodes=ctl.assigned_nodes(self.db,ctl.user(self.db,self.uid))
  self.assertEqual(nodes[0]['name'],'港一')
  self.assertEqual(nodes[0]['protocols'],['hysteria2','trojan'])

if __name__=='__main__':unittest.main()

class MultiNodeTests(ControlTests):
 def test_two_nodes_tag_change_and_offline_revocation(self):
  second='e'*32
  with self.db:self.db.execute('INSERT INTO nodes(id,name,domain,host,ssh_port,ssh_user,ssh_key,mode,sni,tags,state,status,stats_ready) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',
      (second,'港二','hk2.example.com','local',22,'root','','local','www.microsoft.com',json.dumps(['高级']),'active','待同步',1))
  epochs={self.nid:'epoch1',second:'epoch2'}
  def fake_rpc(n,payload):
   principal=payload.get('grants',[{'principal':'m_'+self.uid+'_'+self.cid}])[0]['principal'] if payload.get('grants') else 'm_'+self.uid+'_'+self.cid
   base={'epoch':epochs[n['id']],'sample_at':common.now(),'totals':{principal:{'up':10,'down':20}}}
   if payload['op']=='poll':return base
   if payload['op']=='apply':return dict(base,revision=payload['revision'],grants={g['principal']:[{'type':'trojan','tag':n['name'],'server':n['domain'],'server_port':8445,'password':'secret','tls':{'enabled':True,'server_name':n['domain']}}] for g in payload['grants']})
   raise AssertionError(payload)
  with mock.patch.object(ctl,'rpc',side_effect=fake_rpc):ctl.reconcile(self.db)
  snapshot=json.loads((ctl.PUBLIC_DIR/'published.json').read_text())
  self.assertEqual(len(snapshot[0]['outs']),2)
  with self.db:self.db.execute('UPDATE nodes SET tags=?,status=? WHERE id=?',(json.dumps(['美国']),'待同步',second))
  def offline_second(n,payload):
   if n['id']==second:raise common.Error('offline')
   return fake_rpc(n,payload)
  with mock.patch.object(ctl,'rpc',side_effect=offline_second):ctl.reconcile(self.db)
  snapshot=json.loads((ctl.PUBLIC_DIR/'published.json').read_text())
  self.assertEqual(len(snapshot[0]['outs']),1)
  self.assertIn('待处理',ctl.node(self.db,second)['status'])

class LocalControllerTest(unittest.TestCase):
 def test_local_node_uses_direct_worker_without_ssh(self):
  record={'mode':'local','host':'local','name':'本机','domain':'node.example.com',
          'ssh_port':22,'ssh_user':'root','ssh_key':''}
  calls=[]
  def fake_run(argv,data=None,timeout=0):
   calls.append((argv,json.loads(data)))
   return json.dumps({'ok':True,'result':{'active':True}}).encode()
  with mock.patch.object(ctl,'run',side_effect=fake_run),mock.patch.object(ctl,'ssh_args',side_effect=AssertionError('unexpected SSH')):
   result=ctl.rpc(record,{'op':'inspect'})
  self.assertEqual(result,{'active':True})
  self.assertEqual(calls[0][0][:2],['python3',str(ctl.BUNDLE/'lib/node.py')])

class NodeAccountingTest(unittest.TestCase):
 def test_collect_persists_six_counter_columns(self):
  tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
  old=node_worker.HOME;node_worker.HOME=Path(tmp.name)
  self.addCleanup(setattr,node_worker,'HOME',old)
  db=node_worker.database();self.addCleanup(db.close)
  with mock.patch.object(node_worker,'generation',return_value='boot:1:1'),mock.patch.object(node_worker,'query_stats',return_value={'m_'+('a'*32)+'_'+('b'*32):{'up':12,'down':34}}):
   node_worker.collect(db)
  row=db.execute('SELECT * FROM counters').fetchone()
  self.assertEqual((row['raw_up'],row['raw_down'],row['total_up'],row['total_down']),(12,34,12,34))
