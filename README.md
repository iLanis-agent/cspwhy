# CspWhy

What a Content-Security-Policy actually allows: CSP3 directive fallback chains, source-expression matching, and the traps ('none' combinations, wildcard-vs-bare-domain, elem-vs-attr chains) made visible.

- Landing page: `index.html`
- App: `app.html` (fully client-side, no network calls)
- Engine: `engine.js` - pure functions (`parsePolicy`, `governing`, `matchSource`, `evaluate`), UMD-exported for node tests.

## What it does

Paste a policy and your origin, then ask it questions: inline `<script>`, `onclick=` attributes, inline styles, or any URL as a script / image / fetch / font / iframe / worker / form target. Each verdict (ALLOWED / BLOCKED / CONDITIONAL) names the governing directive, the full fallback chain walked (script-src-elem -> script-src -> default-src; worker-src -> child-src -> script-src -> default-src), and the exact source expression or keyword that decided it. A policy anatomy table shows what each directive governs, what is shadowed, what is contradictory, and what was ignored (unknown or duplicated directives).

## Covered and approximated

Covered: CSP3 fetch-directive chains including elem/attr splits; 'self', 'none' (including the contradictory-combination rule), 'unsafe-inline', nonces, hashes, 'unsafe-hashes'; scheme sources with http->https upgrade; host sources with wildcard subdomains (which exclude the bare domain); port rules incl. non-default ports; data:/blob:-style scheme URLs; duplicate-directive and empty-directive (= 'none') handling.

Approximations (documented, not hidden): path components in host sources are ignored (rare and deprecated); 'strict-dynamic' is parsed but its trust-propagation effect is not modeled; report-uri/report-to and sandbox are shown in the anatomy but not evaluated; frame-ancestors/base-uri/form-action are evaluated as standalone directives with no fallback, as specified.

## Testing

`test/run_tests.js` cross-checks the engine against `test/oracle.py`, an independently written Python implementation of the same rules: 22 hand cases for the classic gotchas plus 600 fuzzed policy/check combinations - 623 cases, 1,269 comparisons, 0 disagreements.

Run: `node test/run_tests.js`

## Live

https://ilanis-agent.github.io/cspwhy/
