#!/usr/bin/env python3
"""Weekly Reality SNI check; rotate only when current target is no longer fully compliant."""
import os
import re
import subprocess
from pathlib import Path
from common import Error, lock, domain
import controller

CHECK=Path('/opt/module/Reality-SNI-Check.sh')

def probe(args, env=None):
    if not CHECK.is_file():raise Error('SNI 检测脚本不存在。')
    p=subprocess.run(['bash',str(CHECK),*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                     text=True,timeout=300,env=env)
    if p.returncode:raise Error('SNI 检测脚本运行失败。')
    return re.sub(r'\x1b\[[0-9;]*m','',p.stdout)

def main():
    if os.geteuid()!=0:raise Error('需要 root。')
    with lock(controller.HOME/'lock'):
        d=controller.database()
        try:
            nodes=d.execute("SELECT * FROM nodes WHERE mode='local' AND state='active' AND stats_ready=1").fetchall()
            if len(nodes)!=1:raise Error('需要恰好一个已登记的本机节点。')
            n=nodes[0];current=domain(n['sni'])
            env=dict(os.environ,SNI_HOSTS=current)
            status=probe(['-n','2','-t','5'],env)
            if any(current in line and '✓ 推荐' in line for line in status.splitlines()):
                print('当前 REALITY SNI 合规，保持：'+current);return
            results=probe(['-c','cdn','-n','2','-t','5'])
            match=re.search(r'→ 建议 dest/SNI:\s*([A-Za-z0-9.-]+)',results)
            if not match or '[全合规]' not in results:
                raise Error('没有全合规候选，保持原 SNI 并等待人工检查。')
            target=domain(match.group(1))
            if target==current:raise Error('检测结果与当前 SNI 不一致；保持原配置。')
            controller.change_sni(d,n,target)
            print('REALITY SNI 已更新并同步订阅：'+target)
        finally:d.close()

if __name__=='__main__':
    try:main()
    except (Error,subprocess.TimeoutExpired) as e:
        print('SNI 检测：'+str(e));raise SystemExit(1)
