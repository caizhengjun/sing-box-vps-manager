"""Client exporters. Naive is deliberately omitted from Mihomo and universal URI lists."""
import base64
import copy
import json
from urllib.parse import quote, urlencode
from common import public_key

def outbounds(config, domain, node_name, username, principal, cred):
    result = []
    display = {'naive': 'Naive', 'vless-reality': 'REALITY', 'vless-ws': 'VLESS WS',
               'trojan': 'Trojan', 'hysteria2': 'Hysteria2', 'tuic': 'TUIC',
               'anytls': 'AnyTLS', 'shadowsocks': 'SS2022'}
    for i in config['inbounds']:
        kind = i['type']
        if i.get('tag') == 'ss-legacy': continue
        if kind not in ('naive','vless','trojan','hysteria2','tuic','anytls','shadowsocks'): continue
        tag = node_name + ' · ' + display.get(i['tag'], i['tag'])
        o = {'type': kind, 'tag': tag, 'server': domain, 'server_port': i['listen_port']}
        for k in ('transport', 'congestion_control', 'method'):
            if k in i: o[k] = copy.deepcopy(i[k])
        if kind == 'shadowsocks':
            o['password'] = i['password'] + ':' + cred['ss']
        else:
            t = i['tls']
            o['tls'] = {'enabled': True, 'server_name': t.get('server_name') or domain}
            if t.get('alpn'): o['tls']['alpn'] = t['alpn']
            r = t.get('reality', {})
            if r.get('enabled'):
                o['tls'].update(utls={'enabled': True, 'fingerprint': 'chrome'},
                                reality={'enabled': True, 'public_key': public_key(r['private_key']),
                                         'short_id': r['short_id'][0]})
                o['flow'] = 'xtls-rprx-vision'
            if kind in ('vless', 'tuic'): o['uuid'] = cred['uuid']
            if kind != 'vless': o['password'] = cred['password']
            if kind == 'naive': o['username'] = principal
        if kind == 'naive':
            o['quic'] = False; o['tag'] = tag + ' H2'; result.append(o)
            o = copy.deepcopy(o); o['quic'] = True; o['tag'] = tag + ' H3'
        result.append(o)
    return result

def singbox(outs, gui=False):
    names = [o['tag'] for o in outs]
    # Full runnable local SOCKS/HTTP client, loopback only, no open proxy.
    config = {'log': {'level': 'info', 'timestamp': True},
            'inbounds': [{'type': 'mixed', 'tag': 'local', 'listen': '127.0.0.1', 'listen_port': 1080}],
            'outbounds': [{'type': 'selector', 'tag': '套餐节点', 'outbounds': names}] + copy.deepcopy(outs),
            'route': {'final': '套餐节点'}}
    if gui:
        config['inbounds'] = [{'type':'tun','tag':'tun-in','address':['172.19.0.1/30'],
                               'mtu':1500,'auto_route':True,'stack':'gvisor'}]
        config['dns'] = {'servers':[
            {'tag':'bootstrap','address':'223.5.5.5','detour':'direct'},
            {'tag':'remote','address':'https://1.1.1.1/dns-query','detour':'套餐节点'}],
            'rules':[{'outbound':'any','server':'bootstrap'}],
            'final':'remote','strategy':'ipv4_only'}
        config['outbounds'].append({'type':'direct','tag':'direct'})
        config['route'].update(auto_detect_interface=True,
            rules=[{'port':53,'action':'hijack-dns'}])
    return config

def mihomo_proxy(o):
    if o['type'] == 'naive': return None
    p = {'name': o['tag'], 'type': 'ss' if o['type'] == 'shadowsocks' else o['type'],
         'server': o['server'], 'port': o['server_port'], 'udp': True}
    for k in ('uuid', 'password', 'flow'):
        if k in o: p[k] = o[k]
    if o['type'] == 'shadowsocks': p['cipher'] = o['method']
    if 'tls' in o:
        t = o['tls']; p['skip-cert-verify'] = False
        # Mihomo VLESS uses servername; Trojan/QUIC/AnyTLS use sni.
        p['servername' if o['type'] == 'vless' else 'sni'] = t['server_name']
        if o['type'] == 'vless': p['tls'] = True
        if t.get('alpn'): p['alpn'] = t['alpn']
        if t.get('reality'):
            p['client-fingerprint'] = 'chrome'
            p['reality-opts'] = {'public-key': t['reality']['public_key'], 'short-id': t['reality']['short_id']}
    tr = o.get('transport', {})
    if tr.get('type') == 'ws':
        p['network'] = 'ws'; p['ws-opts'] = {'path': tr['path'], 'headers': {'Host': o['tls']['server_name']}}
    elif tr.get('type') == 'grpc':
        p['network'] = 'grpc'; p['grpc-opts'] = {'grpc-service-name': tr['service_name']}
    if o['type'] == 'tuic':
        p.update({'congestion-controller': o.get('congestion_control','cubic'), 'reduce-rtt': False})
    return p

def mihomo(outs):
    proxies = [p for o in outs if (p := mihomo_proxy(o)) is not None]
    return {'mixed-port': 1080, 'allow-lan': False, 'bind-address': '127.0.0.1', 'mode': 'rule',
            'proxies': proxies, 'proxy-groups': [{'name': '套餐节点', 'type': 'select',
                                               'proxies': [p['name'] for p in proxies]}],
            'rules': ['MATCH,套餐节点']}

def uri(o):
    kind = o['type']; server = o['server']; port = o['server_port']
    fragment = quote(o['tag'], safe='')
    if kind == 'naive': return None  # No universal cross-client Naive subscription convention.
    if kind == 'shadowsocks':
        user = base64.urlsafe_b64encode((o['method']+':'+o['password']).encode()).decode().rstrip('=')
        return f'ss://{user}@{server}:{port}#{fragment}'
    t = o['tls']; q = {'sni': t['server_name']}
    if t.get('alpn'): q['alpn'] = ','.join(t['alpn'])
    if kind in ('vless', 'trojan'):
        q['security'] = 'reality' if t.get('reality') else 'tls'
        q['type'] = o.get('transport',{}).get('type','tcp')
        if t.get('reality'):
            q.update(pbk=t['reality']['public_key'],sid=t['reality']['short_id'],fp='chrome',flow=o['flow'])
        tr = o.get('transport',{})
        if q['type']=='ws':q.update(path=tr['path'],host=t['server_name'])
        if q['type']=='grpc':q['serviceName']=tr['service_name']
    if kind=='tuic':
        auth=quote(o['uuid'],safe='')+':'+quote(o['password'],safe='')
        q.update(congestion_control=o.get('congestion_control','cubic'),udp_relay_mode='native')
    else: auth=quote(o['uuid'] if kind=='vless' else o['password'],safe='')
    return f'{kind}://{auth}@{server}:{port}?{urlencode(q)}#{fragment}'

def render(outs, fmt):
    # Most packaged sing-box clients omit the optional Naive outbound or force
    # unsupported TLS flags. Keep the primary profile portable; Naive remains
    # available as a separately verified service for clients that ship it.
    if fmt=='singbox':
        portable=[o for o in outs if o['type'] in ('vless','trojan','hysteria2','tuic','shadowsocks')]
        return json.dumps(singbox(portable,gui=True),ensure_ascii=False,indent=2)+'\n','application/json'
    if fmt=='karing':
        return json.dumps(singbox(outs),ensure_ascii=False,indent=2)+'\n','application/json'
    if fmt=='mihomo':
        # JSON is a valid YAML 1.2 document and accepted by Mihomo, no PyYAML dependency.
        return json.dumps(mihomo(outs),ensure_ascii=False,indent=2)+'\n','application/yaml'
    links='\n'.join(v for o in outs if (v:=uri(o)) is not None)+'\n'
    if fmt=='links':return links,'text/plain; charset=utf-8'
    if fmt=='base64':return base64.b64encode(links.encode()).decode()+'\n','text/plain'
    raise ValueError('unsupported format')
