# release-gate (Python / Flask)

Same policy engine as the Node version, ported to Python. `POST /release-gate`
runs `check_policy()` in `app.py`.

## Run locally (no Docker)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py            # dev server on PORT (default 3000)
pytest test/ -q           # run the policy test suite
```

## Run with Docker

```bash
docker build -t release-gate .
docker run -p 3000:3000 -e PORT=3000 release-gate
curl -X POST localhost:3000/release-gate -H 'Content-Type: application/json' -d '{...}'
```

The Dockerfile is multi-stage (build deps in one stage, slim runtime in the
other) and runs as a non-root `appuser`, served via `gunicorn`.

## Deploy on Render

Two options:

1. **Blueprint**: push this repo with `render.yaml` included, then in Render
   choose "New +" → "Blueprint" and point it at the repo. It picks up the
   Dockerfile automatically.
2. **Manual**: "New +" → "Web Service" → connect the repo → Render detects
   the `Dockerfile` and offers Docker as the runtime. Leave the start command
   blank (the Dockerfile's `CMD` handles it); Render injects `PORT`
   automatically and the app already reads `os.environ["PORT"]`.

Once deployed, the public URL's `/release-gate` endpoint is what you give the
grader for the live policy probes.
