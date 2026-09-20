from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


# ============================================================
# Execution Job
# ============================================================

@dataclass
class ExecutionJob:
    """
    Standard job sent from the JOCKY runtime
    to the security provider.
    """

    case_id: str
    target: str
    operation: str
    arguments: dict[str, Any]


# ============================================================
# Execution Result
# ============================================================

@dataclass
class ExecutionResult:
    """
    Standard result returned by the provider.
    """

    success: bool
    provider: str
    started_at: str
    finished_at: str
    data: dict[str, Any]


# ============================================================
# Security Provider
# ============================================================

class SecurityProvider:
    """
    Stable interface between JOCKY and the
    security-control execution layer.

    IMPORTANT:
    The rest of JOCKY should communicate only through
    this interface.
    """

    name = "normal"

    # --------------------------------------------------------
    # Availability
    # --------------------------------------------------------

    def is_available(self) -> bool:
        return True

    # --------------------------------------------------------
    # Authorization
    # --------------------------------------------------------

    def authorize(
        self,
        case: dict[str, Any],
    ) -> bool:

        return bool(
            case.get("authorized", False)
        )

    # --------------------------------------------------------
    # Privilege policy
    # --------------------------------------------------------

    def requires_elevation(
        self,
        job: ExecutionJob,
    ) -> bool:

        return False

    def elevation_method(self) -> str:

        return "none"

    # --------------------------------------------------------
    # Preparation
    # --------------------------------------------------------

    def prepare_execution(
        self,
        job: ExecutionJob,
    ) -> None:

        if not job.case_id:
            raise ValueError(
                "Case ID cannot be empty."
            )

        if not job.target:
            raise ValueError(
                "Target cannot be empty."
            )

        if not job.operation:
            raise ValueError(
                "Operation cannot be empty."
            )

        if not isinstance(
            job.arguments,
            dict,
        ):
            raise TypeError(
                "Job arguments must be a dictionary."
            )

    # --------------------------------------------------------
    # Normal execution
    # --------------------------------------------------------

    def execute(
        self,
        job: ExecutionJob,
    ) -> ExecutionResult:

        self.prepare_execution(job)

        started = datetime.now(
            timezone.utc
        ).isoformat()

        data = {
            "status": "authorized",
            "operation": job.operation,
            "arguments": job.arguments,
        }

        finished = datetime.now(
            timezone.utc
        ).isoformat()

        return ExecutionResult(
            success=True,
            provider=self.name,
            started_at=started,
            finished_at=finished,
            data=data,
        )

    # --------------------------------------------------------
    # Result collection
    # --------------------------------------------------------

    def collect_result(
        self,
        result: ExecutionResult,
    ) -> dict[str, Any]:

        return {
            "success": result.success,
            "provider": result.provider,
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "data": result.data,
        }


# ============================================================
# Provider Factory
# ============================================================

def get_provider() -> SecurityProvider:
    """
    Single factory used by the JOCKY runtime.

    The runtime does not depend on implementation
    details inside this file.
    """

    return SecurityProvider()
