#!/usr/bin/env python3
"""Read-only TLS subscription endpoint. Reads only a sanitized snapshot."""
import asyncio
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import ssl
import sys
from aiohttp import web
from formats import render

HOME=Path('/var/lib/sb-manager')
PUBLIC=Path('/var/lib/sb-subscription/published.json')
CERT=Path('/etc/sb-subscription/fullchain.pem')
KEY=Path('/etc/sb-subscription/privkey.pem')

def fetch(token):
    h=hashlib.sha256(token.encode()).hexdigest()
    for row in json.loads(PUBLIC.read_text()):
        if hmac.compare_digest(row['token_hash'],h):return row
    return None

async def handle(request):
    token=request.match_info['token']
    if len(token)<32 or len(token)>128:return web.Response(status=404)
    try:row=fetch(token)
    except (OSError,ValueError):return web.Response(status=503)
    if not row:return web.Response(status=404)
    if request.path.startswith('/admin/') and not row.get('is_admin'):
        return web.Response(status=404)
    fmt=request.query.get('format','base64')
    if fmt not in ('singbox','karing','mihomo','links','base64'):return web.Response(status=400)
    outs=row['outs']
    body,media=render(outs,fmt) if outs else ('套餐暂无可用节点\n','text/plain')
    headers={'X-Subscription-Start':str(row['started']),
             'Profile-Title':base64.b64encode(row['name'].encode('utf-8')).decode(),
             'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}
    # Absence of quota metadata is the most interoperable representation of an
    # unlimited, non-expiring subscription. total=0/expire=0 is often rendered
    # as "0 B" and "1970-01-01" by mobile clients.
    if not row.get('is_admin'):
        headers['Subscription-Userinfo']=f"upload={row['upload']}; download={row['download']}; total={row['quota']}; expire={row['expires']}"
    return web.Response(status=200 if outs else 403,text=body,content_type=media.split(';')[0],headers=headers)

async def main():
    app=web.Application(client_max_size=1024,middlewares=[])
    app.router.add_get('/sub/{token}',handle,allow_head=True)
    app.router.add_get('/admin/{token}',handle,allow_head=True)
    app.router.add_get('/healthz',lambda request:web.Response(text='ok'))
    runner=web.AppRunner(app,access_log=None,keepalive_timeout=10)
    await runner.setup()
    while True:
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version=ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(str(CERT),str(KEY))
        site=web.TCPSite(runner,'0.0.0.0',443,ssl_context=ctx)
        await site.start()
        # Recreate listener only when certificate changes. Existing requests complete first.
        last=(CERT.stat().st_mtime_ns,KEY.stat().st_mtime_ns)
        while True:
            await asyncio.sleep(30)
            current=(CERT.stat().st_mtime_ns,KEY.stat().st_mtime_ns)
            if current!=last:break
        await site.stop()

if __name__=='__main__':
    asyncio.run(main())
