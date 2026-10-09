# CloseLoop handoff bridge

This bridge turns a completed Cyber Defense campaign JSONL log into a fresh
CloseLoop `exploit-handoff/v1` payload and posts it to
`POST /api/handoffs`. It requires a `passed` `report` event, so an incomplete
campaign cannot trigger remediation.

```sh
python3 bridge/closeloop_handoff.py \
  --events /tmp/cyber-defense-events.jsonl \
  --template ../closeloop/contracts/examples/FIND-002.akash.handoff.json \
  --env-file ../closeloop/.env \
  --closeloop-url "${CLOSELOOP_URL:-http://127.0.0.1:3000}"
```

The env file must provide `CLOSELOOP_INGEST_TOKEN`, `AKASH_LAB_DSEQ`, and
`LAB_BASE_URL`; `AKASH_LAB_SERVICE` defaults to `lab-api`. Existing process
environment values take precedence over the file.

The bridge writes the generated payload to
`/tmp/cyber-defense-handoff.json` by default. It prints only the fresh finding
ID, CloseLoop job ID, and handoff artifact path. It never prints configuration
values, tokens, or response bodies.

Run the isolated bridge tests with:

```sh
python3 -m unittest bridge.test_closeloop_handoff -v
```

The tests use a loopback-only mock HTTP server and make no requests to
CloseLoop, Akash, or GitHub.
