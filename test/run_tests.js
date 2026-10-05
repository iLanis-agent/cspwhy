// Cross-check engine.js against the Python oracle.
const { execFileSync } = require('child_process');
const C = require('../engine.js');

const cases = [];
const ORIGIN = { scheme: 'https', host: 'app.example.com', port: null };

// Hand cases: the classic gotchas
const HAND = [
  ["default-src 'self'", 'script', 'https://app.example.com/a.js', true],
  ["default-src 'self'", 'script', 'https://other.example.com/a.js', false],
  ["default-src 'self'; script-src-elem https://cdn.x.com", 'script', 'https://cdn.x.com/a.js', true], // elem beats script-src
  ["script-src 'none'", 'script', 'https://app.example.com/a.js', false],
  ["script-src 'none' 'self'", 'script', 'https://app.example.com/a.js', false], // contradictory none
  ["script-src 'self'", 'worker', 'https://app.example.com/w.js', true], // worker falls to script-src
  ["default-src 'none'; frame-src https://f.com", 'frame', 'https://f.com/', true],
  ["img-src *.example.com", 'img', 'https://example.com/a.png', false], // wildcard excludes bare domain
  ["img-src *.example.com", 'img', 'https://cdn.example.com/a.png', true],
  ["img-src http:", 'img', 'https://any.com/a.png', true], // scheme upgrade
  ["img-src https:", 'img', 'http://any.com/a.png', false],
  ["img-src data:", 'img', 'data:image/png;base64,xx', true],
  ["img-src data:", 'img', 'https://any.com/a.png', false],
  ["connect-src 'self'", 'connect', 'https://app.example.com:8443/api', false], // non-default port
  ["script-src 'self'", 'script', null, 'INLINE_BLOCKS'],
  ["script-src 'self' 'unsafe-inline'", 'script', null, 'INLINE_OK'],
  ["script-src 'nonce-abc123'", 'script', null, 'INLINE_CONDITIONAL'],
  ["script-src-attr 'unsafe-hashes' 'sha256-x8+='", 'script-attr', null, 'INLINE_OK'],
  ["style-src 'self'", 'style-attr', null, 'INLINE_BLOCKS'],
  ["form-action 'self'", 'form-action', 'https://app.example.com/submit', true],
  ["", 'form-action', 'https://evil.com/x', true], // no form-action = unrestricted
  ["", 'script', 'https://evil.com/x', true], // empty policy = unrestricted
  ["default-src", 'script', 'https://app.example.com/a.js', false], // empty directive = 'none'
];
HAND.forEach(([policy, type, url, want]) => {
  const check = url === null ? { type, inline: true } : { type, url };
  cases.push({ policy, origin: ORIGIN, check, want });
});

// Fuzz
const SRCS = ["'self'", "'none'", "'unsafe-inline'", 'https:', 'http:', 'data:', 'blob:', '*',
  'https://cdn.example.com', '*.example.com', 'example.com', 'https://static.example.com:8443',
  "'nonce-xyz'", "'sha256-abc='", "'unsafe-hashes'", "'strict-dynamic'"];
const DIRS = ['default-src', 'script-src', 'script-src-elem', 'script-src-attr', 'style-src',
  'style-src-elem', 'style-src-attr', 'img-src', 'connect-src', 'font-src', 'media-src',
  'object-src', 'frame-src', 'child-src', 'worker-src', 'form-action', 'base-uri'];
const TYPES = Object.keys(C.CHAINS).concat(['form-action', 'base-uri']);
const URLS = ['https://app.example.com/a.js', 'https://cdn.example.com/a.js', 'https://example.com/a.js',
  'http://app.example.com/a.js', 'https://static.example.com:8443/a.js', 'data:image/png;base64,xx',
  'blob:https://app.example.com/uuid', 'https://deep.cdn.example.com/x', 'https://evil.com/x.js',
  'ftp://files.example.com/x'];
function ri(n) { return Math.floor(Math.random() * n); }
for (let i = 0; i < 600; i++) {
  const nd = 1 + ri(4);
  const parts = [];
  for (let j = 0; j < nd; j++) {
    const dir = DIRS[ri(DIRS.length)];
    const ns = 1 + ri(3);
    parts.push(dir + ' ' + Array.from({ length: ns }, () => SRCS[ri(SRCS.length)]).join(' '));
  }
  const type = TYPES[ri(TYPES.length)];
  const check = Math.random() < 0.3 ? { type, inline: true } : { type, url: URLS[ri(URLS.length)] };
  cases.push({ policy: parts.join('; '), origin: ORIGIN, check });
}

const oracle = JSON.parse(execFileSync('python3', ['test/oracle.py'], { input: JSON.stringify(cases), maxBuffer: 1 << 25 }).toString());
let fails = 0, checked = 0;
cases.forEach((c, i) => {
  const parsed = C.parsePolicy(c.policy);
  const js = C.evaluate(parsed, c.origin, c.check);
  const py = oracle[i];
  checked++;
  const jsA = js.allowed, pyA = py.allowed;
  if (jsA !== pyA) { fails++; if (fails <= 8) console.log('ALLOWED MISMATCH', i, JSON.stringify(c), 'js', jsA, 'py', pyA); }
  checked++;
  const jsD = js.directive || null, pyD = py.directive || null;
  if (jsD !== pyD) { fails++; if (fails <= 8) console.log('DIRECTIVE MISMATCH', i, JSON.stringify(c), 'js', jsD, 'py', pyD); }
});
// Hand-case expectations
HAND.forEach(([policy, type, url, want], i) => {
  const parsed = C.parsePolicy(policy);
  const check = url === null ? { type, inline: true } : { type, url };
  const r = C.evaluate(parsed, ORIGIN, check);
  checked++;
  const ok = want === 'INLINE_OK' ? r.allowed === true :
             want === 'INLINE_BLOCKS' ? r.allowed === false :
             want === 'INLINE_CONDITIONAL' ? r.allowed === 'conditional' :
             r.allowed === want;
  if (!ok) { fails++; console.log('HAND FAIL', i, policy, type, url, 'got', JSON.stringify(r)); }
});
console.log(`cases=${cases.length} checked=${checked} fails=${fails}`);
process.exit(fails ? 1 : 0);
