import os
import hmac
import shutil
from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="APOSTULOS Kali Bridge", version="1.0.0")
TOKEN = os.environ.get("APOSTULOS_AGENT_TOKEN", "")

TOOLS = {
    "nmap": "nmap",
    "nuclei": "nuclei",
    "nikto": "nikto",
    "sqlmap": "sqlmap",
    "whatweb": "whatweb",
    "wapiti": "wapiti",
    "tshark": "tshark",
}

def authorize(value: str | None):
    if not TOKEN or not value or not hmac.compare_digest(value, TOKEN):
        raise HTTPException(status_code=401, detail="Token APOSTULOS inválido")

@app.get("/health")
def health():
    return {"status": "ok", "service": "apostulos-kali-bridge"}

@app.get("/api/v1/capabilities")
def capabilities(x_apostulos_agent: str | None = Header(default=None)):
    authorize(x_apostulos_agent)
    return {
        "platform": "Kali Linux",
        "agent_version": "1.0.0",
        "mode": "inventory-only",
        "tools": {name: shutil.which(binary) is not None for name, binary in TOOLS.items()},
        "execution_enabled": False,
    }
