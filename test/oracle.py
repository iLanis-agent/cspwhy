"""Independent CSP3 subset reference for cross-checking engine.js."""
import json, sys, re

CHAINS = {
    'script': ['script-src-elem', 'script-src', 'default-src'],
    'script-attr': ['script-src-attr', 'script-src', 'default-src'],
    'style': ['style-src-elem', 'style-src', 'default-src'],
    'style-attr': ['style-src-attr', 'style-src', 'default-src'],
    'img': ['img-src', 'default-src'],
    'connect': ['connect-src', 'default-src'],
    'font': ['font-src', 'default-src'],
    'media': ['media-src', 'default-src'],
    'object': ['object-src', 'default-src'],
    'manifest': ['manifest-src', 'default-src'],
    'prefetch': ['prefetch-src', 'default-src'],
    'frame': ['frame-src', 'child-src', 'default-src'],
    'worker': ['worker-src', 'child-src', 'script-src', 'default-src'],
    'child': ['child-src', 'default-src'],
}
DEFAULT_PORTS = {'http': 80, 'https': 443, 'ws': 80, 'wss': 443, 'ftp': 21}

def parse_policy(s):
    d, order, warnings = {}, [], []
    for part in str(s or '').split(';'):
        part = part.strip()
        if not part:
            continue
        toks = part.split()
        name = toks[0].lower()
        if name in d:
            warnings.append(name)
            continue
        d[name] = toks[1:]
        order.append(name)
    return d, warnings

def parse_url(u):
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/:?#]+)(?::(\d+))?([/?#]|$)", u)
    if m:
        return {'scheme': m.group(1).lower(), 'host': m.group(2).lower(),
                'port': int(m.group(3)) if m.group(3) else None, 'hier': True}
    m2 = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):", u)
    if m2:
        return {'scheme': m2.group(1).lower(), 'host': None, 'port': None, 'hier': False}
    return None

def match_source(expr, url, origin):
    expr = expr.lower()
    if expr.startswith("'"):
        return False
    u = parse_url(url)
    if not u:
        return False
    if re.match(r"^[a-z]+:$", expr):
        es = expr[:-1]
        if not u['hier']:
            return u['scheme'] == es
    sm = re.match(r"^([a-z][a-z0-9+.-]*):$", expr)
    if sm:
        if not u['hier']:
            return False
        ps = sm.group(1)
        if u['scheme'] == ps:
            return True
        return (ps == 'http' and u['scheme'] == 'https') or (ps == 'ws' and u['scheme'] == 'wss')
    h = expr
    scheme_pat = None
    hm = re.match(r"^(\*|[a-z][a-z0-9+.-]*)://(.+)$", h)
    if hm:
        scheme_pat, h = hm.group(1), hm.group(2)
    if '/' in h:
        h = h.split('/', 1)[0]
    port_pat = None
    pm = re.match(r"^(.*):(\d+|\*)$", h)
    if pm:
        h, port_pat = pm.group(1), pm.group(2)
    if not u['hier']:
        return False
    if scheme_pat:
        if scheme_pat == '*':
            if u['scheme'] not in ('http', 'https', 'ws', 'wss'):
                return False
        elif u['scheme'] != scheme_pat:
            if not ((scheme_pat == 'http' and u['scheme'] == 'https') or (scheme_pat == 'ws' and u['scheme'] == 'wss')):
                return False
    else:
        if origin and origin.get('scheme'):
            if u['scheme'] != origin['scheme']:
                up = (origin['scheme'] == 'http' and u['scheme'] == 'https') or (origin['scheme'] == 'ws' and u['scheme'] == 'wss')
                if not up:
                    return False
    if port_pat:
        if port_pat != '*':
            actual = u['port'] if u['port'] is not None else DEFAULT_PORTS.get(u['scheme'])
            if actual != int(port_pat):
                return False
    else:
        if u['port'] is not None and DEFAULT_PORTS.get(u['scheme']) != u['port']:
            if not (origin and origin.get('port') == u['port']):
                return False
    if h == '*':
        return True
    if h.startswith('*.'):
        base = h[2:]
        if u['host'] == base:
            return False
        return u['host'].endswith('.' + base) and len(u['host']) > len(base)
    return u['host'] == h

def evaluate(policy_str, origin, check):
    directives, _ = parse_policy(policy_str)
    t = check['type']
    if t in ('form-action', 'base-uri', 'frame-ancestors'):
        if t not in directives:
            return {'allowed': True, 'directive': None}
        return decide(directives[t], t, check, origin)
    chain = CHAINS[t]
    directive = next((c for c in chain if c in directives), None)
    if directive is None:
        return {'allowed': True, 'directive': None}
    return decide(directives[directive], directive, check, origin)

def decide(values, directive, check, origin):
    if not values:
        return {'allowed': False, 'directive': directive}
    if "'none'" in values:
        return {'allowed': False, 'directive': directive}
    if check.get('inline'):
        if "'unsafe-inline'" in values:
            return {'allowed': True, 'directive': directive}
        nonce = next((v for v in values if re.match(r"^'nonce-[A-Za-z0-9+/=_-]+'$", v)), None)
        hash_ = next((v for v in values if re.match(r"^'(sha256|sha384|sha512)-[A-Za-z0-9+/=]+'$", v)), None)
        if check['type'] in ('script-attr', 'style-attr'):
            if "'unsafe-hashes'" in values and hash_:
                return {'allowed': True, 'directive': directive}
            return {'allowed': False, 'directive': directive}
        if nonce or hash_:
            return {'allowed': 'conditional', 'directive': directive}
        return {'allowed': False, 'directive': directive}
    u = parse_url(check.get('url', ''))
    for v in values:
        if v == "'self'":
            if (u and u['hier'] and origin and u['scheme'] == origin['scheme'] and u['host'] == origin['host']
                    and (u['port'] or DEFAULT_PORTS.get(u['scheme'])) == (origin.get('port') or DEFAULT_PORTS.get(origin['scheme']))):
                return {'allowed': True, 'directive': directive}
            continue
        if v.startswith("'"):
            continue
        if match_source(v, check.get('url', ''), origin):
            return {'allowed': True, 'directive': directive}
    return {'allowed': False, 'directive': directive}

cases = json.load(sys.stdin)
print(json.dumps([evaluate(c['policy'], c['origin'], c['check']) for c in cases]))
