"""
Core environment implementation for Cyber-Sentinel.

Wraps the task classes and provides the standard OpenEnv
`reset()` / `step()` / `state` interface.
"""

from __future__ import annotations

from typing import Any, Optional

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import EnvironmentMetadata

import sys, os

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from models import CyberSentinelAction, CyberSentinelObservation, CyberSentinelState
from server.tasks import TASK_REGISTRY, BaseTask


class CyberSentinelEnvironment(
    Environment[CyberSentinelAction, CyberSentinelObservation, CyberSentinelState]
):
    """
    Cyber-Sentinel Environment.

    Simulates three real-world cybersecurity operations tasks:
      1. SIEM Alert Triage (easy)
      2. Forensic Threat Hunting (medium)
      3. Cloud Perimeter Hardening (hard)
    """

    SUPPORTS_CONCURRENT_SESSIONS = True

    def __init__(
        self,
        task_name: str = "alert_triage",
        seed: int = 42,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self._task_name = task_name
        self._seed = seed
        self._task: Optional[BaseTask] = None
        self._step_count = 0

    # ── OpenEnv interface ────────────────────────────────────────────────

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> CyberSentinelObservation:
        self._reset_rubric()

        if seed is not None:
            self._seed = seed

        task_name = kwargs.get("task_name", self._task_name)
        if task_name in TASK_REGISTRY:
            self._task_name = task_name

        task_cls = TASK_REGISTRY[self._task_name]
        self._task = task_cls(seed=self._seed)
        self._step_count = 0

        return self._make_observation(reward=None, done=False)

    def step(
        self,
        action: CyberSentinelAction,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> CyberSentinelObservation:
        if self._task is None:
            return CyberSentinelObservation(
                task_name=self._task_name,
                task_description="Environment not reset. Call reset() first.",
                done=True,
                reward=0.0,
                last_action_success=False,
                last_action_error="Environment not initialized. Call /reset first.",
                current_score=0.0,
            )

        self._step_count += 1

        params = action.model_dump(
            exclude={"action_type", "metadata"},
            exclude_none=True,
        )

        reward_delta, done = self._task.step(action.action_type, params)

        obs = self._make_observation(
            reward=self._task.score,
            done=done,
        )
        obs.last_action_success = self._task._last_action_success
        obs.last_action_error = self._task._last_action_error
        obs.reward = reward_delta

        return obs

    @property
    def state(self) -> CyberSentinelState:
        if self._task is None:
            return CyberSentinelState(
                task_name=self._task_name,
                step_count=0,
                done=True,
            )

        return CyberSentinelState(
            task_name=self._task_name,
            step_count=self._step_count,
            task_data=self._task.get_task_data(),
            score=self._task.score,
            done=self._task.done,
        )

    def get_metadata(self) -> EnvironmentMetadata:
        return EnvironmentMetadata(
            name="Cyber-Sentinel Environment",
            description=(
                "Simulates real-world cybersecurity operations: "
                "SIEM alert triage, forensic threat hunting, "
                "and cloud perimeter hardening."
            ),
            version="0.1.0",
        )

    # ── Helpers ──────────────────────────────────────────────────────────

    def _make_observation(
        self,
        reward: Optional[float],
        done: bool,
    ) -> CyberSentinelObservation:
        task_fields = self._task.get_observation_fields() if self._task else {}

        return CyberSentinelObservation(
            task_name=self._task_name,
            task_description=self._task.description if self._task else "",
            step_count=self._step_count,
            max_steps=self._task.max_steps if self._task else 0,
            done=done,
            reward=reward,
            current_score=self._task.score if self._task else 0.0,
            last_action_success=True,
            last_action_error=None,
            **task_fields,
        )
