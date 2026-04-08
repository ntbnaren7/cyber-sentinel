"""
FastAPI application entry point for the Cyber-Sentinel Environment.

Provides both:
  1. Standard OpenEnv routes (via HTTPEnvServer.register_routes)
  2. Stateful HTTP routes for agent interaction (/env/reset, /env/step, /env/state)
"""

from __future__ import annotations

import logging
import os
import sys
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

load_dotenv()

# ── Path setup ──────────────────────────────────────────────────────────
SERVER_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SERVER_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# ── Logging ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# ── Imports ─────────────────────────────────────────────────────────────
from openenv.core.env_server.http_server import HTTPEnvServer

from models import CyberSentinelAction, CyberSentinelObservation
from server.environment import CyberSentinelEnvironment


# ── Environment factory ────────────────────────────────────────────────
DEFAULT_TASK = os.getenv("CYBER_SENTINEL_TASK", "alert_triage")
DEFAULT_SEED = int(os.getenv("CYBER_SENTINEL_SEED", "42"))


def create_environment() -> CyberSentinelEnvironment:
    """Factory function invoked by HTTPEnvServer for each session."""
    return CyberSentinelEnvironment(task_name=DEFAULT_TASK, seed=DEFAULT_SEED)


# ── Session store for stateful HTTP ────────────────────────────────────
_sessions: Dict[str, CyberSentinelEnvironment] = {}


# ── Request/Response models for stateful routes ────────────────────────

class StatefulResetRequest(BaseModel):
    seed: Optional[int] = Field(default=42, description="Random seed")
    task_name: Optional[str] = Field(default="alert_triage", description="Task to run")
    session_id: Optional[str] = Field(default=None, description="Reuse an existing session")


class StatefulStepRequest(BaseModel):
    session_id: str = Field(..., description="Session ID from reset")
    action: Dict[str, Any] = Field(..., description="Action to execute")


class StatefulStateRequest(BaseModel):
    session_id: str = Field(..., description="Session ID")


# ── Lifespan ────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Cyber-Sentinel Environment server...")

    http_server = HTTPEnvServer(
        env=create_environment,
        action_cls=CyberSentinelAction,
        observation_cls=CyberSentinelObservation,
    )
    http_server.register_routes(app)

    logger.info("OpenEnv routes registered successfully.")
    yield

    for sid in list(_sessions.keys()):
        _sessions[sid].close()
    _sessions.clear()
    logger.info("Shutting down Cyber-Sentinel Environment server.")


# ── FastAPI app ─────────────────────────────────────────────────────────
app = FastAPI(
    lifespan=lifespan,
    title="Cyber-Sentinel Environment",
    description=(
        "An OpenEnv-compliant environment simulating real-world cybersecurity "
        "operations: SIEM alert triage, forensic threat hunting, and cloud "
        "perimeter hardening."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", include_in_schema=False)
async def root():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/docs")


# ═══════════════════════════════════════════════════════════════════════════
# Stateful HTTP endpoints (for agent inference)
# ═══════════════════════════════════════════════════════════════════════════

@app.post("/env/reset")
async def env_reset(req: StatefulResetRequest):
    sid = req.session_id or str(uuid.uuid4())

    if sid in _sessions:
        _sessions[sid].close()

    task_name = req.task_name or DEFAULT_TASK
    seed = req.seed if req.seed is not None else DEFAULT_SEED

    env = CyberSentinelEnvironment(task_name=task_name, seed=seed)
    obs = env.reset(seed=seed, task_name=task_name)

    _sessions[sid] = env

    return {
        "session_id": sid,
        "observation": obs.model_dump(),
        "reward": obs.reward,
        "done": obs.done,
    }


@app.post("/env/step")
async def env_step(req: StatefulStepRequest):
    env = _sessions.get(req.session_id)
    if env is None:
        raise HTTPException(
            status_code=404,
            detail=f"Session {req.session_id} not found. Call /env/reset first.",
        )

    try:
        action = CyberSentinelAction(**req.action)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Invalid action: {e}")

    obs = env.step(action)

    if obs.done:
        env.close()
        del _sessions[req.session_id]

    return {
        "observation": obs.model_dump(),
        "reward": obs.reward,
        "reward_delta": obs.metadata.get("reward_delta", 0.0) if obs.metadata else 0.0,
        "done": obs.done,
    }


@app.post("/env/state")
async def env_state(req: StatefulStateRequest):
    env = _sessions.get(req.session_id)
    if env is None:
        raise HTTPException(
            status_code=404, detail=f"Session {req.session_id} not found."
        )

    return {"state": env.state.model_dump()}


# ── CLI entry point ────────────────────────────────────────────────────
def main(host: str = "0.0.0.0", port: int | None = None):
    import uvicorn
    if port is None:
        port = int(os.getenv("API_PORT", "7860"))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
