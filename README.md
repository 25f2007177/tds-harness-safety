# TDS Harness Safety Classifier

FastAPI endpoint for profile `agent-harness-2026-09`.

## Local run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

Health check: `GET http://127.0.0.1:8000/`

POST endpoint: `http://127.0.0.1:8000/classify`

Deploy on Render using the included `render.yaml`, or create a Python web service with:
- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`

The classifier is deterministic and stateless. It is a baseline implementation; run the assignment's Check against it and use the returned feedback to refine the rules before Save.
