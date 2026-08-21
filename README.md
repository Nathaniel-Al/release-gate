# release-gate

Deterministic policy endpoint for `POST /release-gate`. See `server.js` for the
rule engine (`checkPolicy`) and `test/run-tests.js` for the full behavioral
test suite (safe payloads, single violations, and multi-failure combinations).

## Run locally

```bash
npm install
npm start        # starts the HTTP server on PORT (default 3000)
npm test         # runs the policy test suite (no server needed)
```

## Deploy

Deploy `server.js` to any Node host (Render, Railway, Fly.io, a VM, etc.) and
expose `POST /release-gate` publicly. The service reads `PORT` from the
environment.

## GitHub Actions evidence

`.github/workflows/tds-ga7-release-gate.yml` is named exactly
`TDS GA7 Release Gate`, triggers on `push` to `main`, contains a step named
exactly `TDS identity: 25ds3000071@ds.study.iitm.ac.in`, and runs
`npm test` against the policy engine. Submit the **workflow page URL**
(e.g. `https://github.com/<user>/<repo>/actions/workflows/tds-ga7-release-gate.yml`),
not an individual run URL.
