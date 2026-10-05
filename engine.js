/* CspWhy engine: parse a Content-Security-Policy and answer "is this allowed?"
   per CSP3 fetch-directive fallback chains and source-expression matching.
   Pure functions, no DOM. Documented subset: see README for approximations. */
(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  root.CspWhy = api;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // CSP3 fallback chains for fetch directives (most specific first).
  var CHAINS = {
    'script':       ['script-src-elem', 'script-src', 'default-src'],
    'script-attr':  ['script-src-attr', 'script-src', 'default-src'],
    'style':        ['style-src-elem', 'style-src', 'default-src'],
    'style-attr':   ['style-src-attr', 'style-src', 'default-src'],
    'img':          ['img-src', 'default-src'],
    'connect':      ['connect-src', 'default-src'],
    'font':         ['font-src', 'default-src'],
    'media':        ['media-src', 'default-src'],
    'object':       ['object-src', 'default-src'],
    'manifest':     ['manifest-src', 'default-src'],
    'prefetch':     ['prefetch-src', 'default-src'],
    'frame':        ['frame-src', 'child-src', 'default-src'],
    'worker':       ['worker-src', 'child-src', 'script-src', 'default-src'],
    'child':        ['child-src', 'default-src']
  };
  // Directives with no fallback: absence means "no restriction" (form-action,
  // base-uri) or "allowed everywhere" (frame-ancestors). Handled specially.

  var KEYWORDS = ["'self'", "'unsafe-inline'", "'unsafe-eval'", "'none'",
                  "'strict-dynamic'", "'unsafe-hashes'", "'report-sample'",
                  "'unsafe-allow-redirects'", "'wasm-unsafe-eval'", "'inline-speculation-rules'"];

  function parsePolicy(str) {
    var directives = {};
    var order = [];
    var warnings = [];
    var src = String(str == null ? '' : str);
    var parts = src.split(';');
    for (var i = 0; i < parts.length; i++) {
      var p = parts[i].trim();
      if (!p) continue;
      var tokens = p.split(/\s+/);
      var name = tokens[0].toLowerCase();
      var values = tokens.slice(1);
      if (directives[name]) {
        warnings.push('"' + name + '" appears again ("' + p + '") - per spec the first occurrence wins and this one is ignored.');
        continue;
      }
      directives[name] = { values: values, raw: p };
      order.push(name);
    }
    return { directives: directives, order: order, warnings: warnings };
  }

  // Which directive governs a check type: walk the chain, first present wins.
  function governing(policy, checkType) {
    var chain = CHAINS[checkType];
    if (!chain) return { directive: null, chain: [] };
    for (var i = 0; i < chain.length; i++) {
      if (policy.directives[chain[i]]) {
        return { directive: chain[i], chain: chain.slice(0, i + 1) };
      }
    }
    return { directive: null, chain: chain };
  }

  function parseUrl(url) {
    var m = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/:?#]+)(?::(\d+))?([/?#]|$)/.exec(url);
    if (m) {
      return { scheme: m[1].toLowerCase(), host: m[2].toLowerCase(),
               port: m[3] ? parseInt(m[3], 10) : null, hierarchical: true };
    }
    var m2 = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(url);
    if (m2) return { scheme: m2[1].toLowerCase(), host: null, port: null, hierarchical: false };
    return null;
  }

  var DEFAULT_PORTS = { http: 80, https: 443, ws: 80, wss: 443, ftp: 21 };

  // Does one source expression match a URL, given the protected origin?
  function matchSource(expr, url, origin) {
    expr = expr.toLowerCase();
    if (expr.charAt(0) === "'") return { match: false }; // keywords handled by caller
    var u = parseUrl(url);
    if (!u) return { match: false };

    // Non-hierarchical scheme sources: data:, blob:, filesystem:, mediastream:
    if (/^[a-z]+:$/.test(expr)) {
      var es = expr.slice(0, -1);
      if (!u.hierarchical) {
        if (u.scheme === es) return { match: true, via: "'" + es + ":' scheme source matches " + u.scheme + ' URL' };
        return { match: false };
      }
      // Scheme-source like https: handled below (it parses as scheme only).
    }
    // Scheme-only source (https:)
    var sm = /^([a-z][a-z0-9+.-]*):$/.exec(expr);
    if (sm && !u.hierarchical) return { match: false };
    if (sm) {
      var ps = sm[1];
      if (u.scheme === ps) return { match: true, via: "scheme '" + ps + ":'" };
      // Scheme upgrade: http/ws in policy also matches the tls variant.
      if ((ps === 'http' && u.scheme === 'https') || (ps === 'ws' && u.scheme === 'wss')) {
        return { match: true, via: "scheme upgrade (http: covers https)" };
      }
      return { match: false };
    }

    // Host source: [*://]host[:port][/path]
    var h = expr;
    var schemePat = null;
    var hm = /^(\*|[a-z][a-z0-9+.-]*):\/\/(.+)$/.exec(h);
    if (hm) { schemePat = hm[1]; h = hm[2]; }
    var pathIdx = h.indexOf('/');
    if (pathIdx >= 0) h = h.slice(0, pathIdx); // path matching approximated: see README
    var portPat = null;
    var pm = /^(.*):(\d+|\*)$/.exec(h);
    if (pm) { h = pm[1]; portPat = pm[2]; }
    if (!u.hierarchical) return { match: false };

    // Scheme check
    if (schemePat) {
      if (schemePat === '*') {
        if (['http', 'https', 'ws', 'wss'].indexOf(u.scheme) < 0) return { match: false };
      } else if (u.scheme !== schemePat) {
        if (!((schemePat === 'http' && u.scheme === 'https') || (schemePat === 'ws' && u.scheme === 'wss'))) return { match: false };
      }
    } else {
      // No scheme in source: matches the protected resource's scheme (or better).
      if (origin && origin.scheme) {
        if (u.scheme !== origin.scheme) {
          var upgraded = (origin.scheme === 'http' && u.scheme === 'https') || (origin.scheme === 'ws' && u.scheme === 'wss');
          if (!upgraded) return { match: false };
        }
      }
    }
    // Port check
    if (portPat) {
      if (portPat !== '*') {
        var want = parseInt(portPat, 10);
        var actual = u.port != null ? u.port : DEFAULT_PORTS[u.scheme];
        if (actual !== want) return { match: false };
      }
    } else {
      if (u.port != null && DEFAULT_PORTS[u.scheme] !== u.port) {
        // Non-default port with no port in source: no match.
        if (!(origin && origin.port === u.port)) return { match: false };
      }
    }
    // Host check
    if (h === '*') return { match: true, via: 'any host (*)' };
    var host = h;
    if (host.slice(0, 2) === '*.') {
      var base = host.slice(2);
      if (u.host === base) return { match: false }; // *.example.com excludes the bare domain
      if (u.host.length > base.length && u.host.slice(-(base.length + 1)) === '.' + base) {
        return { match: true, via: "'*." + base + "' matches subdomain " + u.host };
      }
      return { match: false };
    }
    if (u.host === host) return { match: true, via: 'host ' + host };
    return { match: false };
  }

  // Evaluate a check: {type, url?, inlineAttr?} against a policy object, with origin.
  function evaluate(policyObj, origin, check) {
    var type = check.type;
    // Non-fetch directives: no fallback, absence = unrestricted.
    if (type === 'form-action' || type === 'base-uri' || type === 'frame-ancestors') {
      var d = policyObj.directives[type];
      if (!d) return { allowed: true, directive: null, chain: [],
        reason: 'no ' + type + ' directive, so it is unrestricted' };
      return decideWithSourceList(d, type, [type], check, origin);
    }
    var g = governing(policyObj, type);
    if (!g.directive) {
      return { allowed: true, directive: null, chain: g.chain,
        reason: 'no directive in the ' + g.chain.join(' -> ') + ' chain, so it is unrestricted' };
    }
    return decideWithSourceList(policyObj.directives[g.directive], g.directive, g.chain, check, origin);
  }

  function decideWithSourceList(directive, directiveName, chain, check, origin) {
    var values = directive.values;
    var via = chain.length > 1 ? ' (via ' + chain.join(' -> ') + ')' : '';
    if (values.length === 0) {
      return { allowed: false, directive: directiveName, chain: chain,
        reason: directiveName + ' is present but empty, which equals \'none\'' + via };
    }
    var hasNone = values.indexOf("'none'") >= 0;
    if (hasNone) {
      if (values.length > 1) {
        return { allowed: false, directive: directiveName, chain: chain,
          reason: "'none' combined with other sources is contradictory; browsers honor 'none' and block" + via };
      }
      return { allowed: false, directive: directiveName, chain: chain,
        reason: directiveName + " is 'none'" + via };
    }
    // Inline checks: inline script element, inline event handler attribute, style element/attribute.
    if (check.inline) {
      if (values.indexOf("'unsafe-inline'") >= 0) {
        return { allowed: true, directive: directiveName, chain: chain,
          reason: "'unsafe-inline' is present in " + directiveName + via };
      }
      var nonceRe = /^'nonce-[A-Za-z0-9+\/=_-]+'$/;
      var hashRe = /^'(sha256|sha384|sha512)-[A-Za-z0-9+\/=]+'$/;
      var nonce = values.filter(function (v) { return nonceRe.test(v); })[0];
      var hash = values.filter(function (v) { return hashRe.test(v); })[0];
      if (check.type === 'script-attr' || check.type === 'style-attr') {
        if (values.indexOf("'unsafe-hashes'") >= 0 && hash) {
          return { allowed: true, directive: directiveName, chain: chain,
            reason: "'unsafe-hashes' plus a hash source can allow a matching inline attribute" + via };
        }
        return { allowed: false, directive: directiveName, chain: chain,
          reason: 'inline attributes are only allowed by \'unsafe-inline\' (or a matching hash with \'unsafe-hashes\')' + via };
      }
      if (nonce) return { allowed: 'conditional', directive: directiveName, chain: chain,
        reason: 'allowed only if the element carries ' + nonce + via };
      if (hash) return { allowed: 'conditional', directive: directiveName, chain: chain,
        reason: 'allowed only if the element\'s content hashes to ' + hash + via };
      return { allowed: false, directive: directiveName, chain: chain,
        reason: 'no \'unsafe-inline\', nonce, or hash in ' + directiveName + via };
    }
    // URL checks
    var url = check.url || '';
    var u = parseUrl(url);
    for (var i = 0; i < values.length; i++) {
      var v = values[i];
      if (v === "'self'") {
        if (u && u.hierarchical && origin && u.scheme === origin.scheme && u.host === origin.host &&
            (u.port || DEFAULT_PORTS[u.scheme]) === (origin.port || DEFAULT_PORTS[origin.scheme])) {
          return { allowed: true, directive: directiveName, chain: chain,
            reason: "'self' matches the protected origin " + origin.scheme + '://' + origin.host + via };
        }
        continue;
      }
      if (v.charAt(0) === "'") continue; // other keywords irrelevant to URLs
      var m = matchSource(v, url, origin);
      if (m.match) {
        return { allowed: true, directive: directiveName, chain: chain,
          reason: 'matched source "' + v + '" in ' + directiveName + via };
      }
    }
    return { allowed: false, directive: directiveName, chain: chain,
      reason: 'no source in ' + directiveName + ' matches ' + url + via };
  }

  return {
    CHAINS: CHAINS,
    parsePolicy: parsePolicy,
    governing: governing,
    parseUrl: parseUrl,
    matchSource: matchSource,
    evaluate: evaluate
  };
});
