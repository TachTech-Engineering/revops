"""
Workflow Execution Context

Manages the state and data flow during workflow execution.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from uuid import UUID


@dataclass
class StepOutput:
    """Output from a single workflow step."""
    node_key: str
    status: str  # completed, failed, skipped
    output: dict[str, Any]
    error: Optional[str] = None
    duration_ms: Optional[int] = None


@dataclass
class LoopState:
    """State for tracking loop iteration."""
    items: list[Any]
    current_index: int = 0

    @property
    def current_item(self) -> Any:
        if self.current_index < len(self.items):
            return self.items[self.current_index]
        return None

    @property
    def is_complete(self) -> bool:
        return self.current_index >= len(self.items)


@dataclass
class ExecutionContext:
    """
    Holds all state during workflow execution.

    Provides access to:
    - trigger: The data that triggered the workflow
    - steps: Outputs from completed steps
    - variables: Workflow-level variables
    - loop: Current loop state (if in a loop)
    """
    execution_id: UUID
    workflow_id: UUID
    trigger_data: dict[str, Any]
    variables: dict[str, Any] = field(default_factory=dict)
    steps: dict[str, StepOutput] = field(default_factory=dict)
    loop_stack: list[LoopState] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.utcnow)

    def set_step_output(self, node_key: str, output: dict[str, Any], status: str = "completed",
                        error: Optional[str] = None, duration_ms: Optional[int] = None) -> None:
        """Record the output of a completed step."""
        self.steps[node_key] = StepOutput(
            node_key=node_key,
            status=status,
            output=output,
            error=error,
            duration_ms=duration_ms,
        )

    def get_step_output(self, node_key: str) -> Optional[dict[str, Any]]:
        """Get the output from a specific step."""
        step = self.steps.get(node_key)
        return step.output if step else None

    def set_variable(self, name: str, value: Any) -> None:
        """Set a workflow variable."""
        self.variables[name] = value

    def get_variable(self, name: str, default: Any = None) -> Any:
        """Get a workflow variable."""
        return self.variables.get(name, default)

    def push_loop(self, items: list[Any]) -> None:
        """Start a new loop iteration."""
        self.loop_stack.append(LoopState(items=items))

    def pop_loop(self) -> Optional[LoopState]:
        """End the current loop."""
        if self.loop_stack:
            return self.loop_stack.pop()
        return None

    def advance_loop(self) -> bool:
        """Move to the next loop item. Returns True if more items remain."""
        if not self.loop_stack:
            return False
        self.loop_stack[-1].current_index += 1
        return not self.loop_stack[-1].is_complete

    @property
    def current_loop(self) -> Optional[LoopState]:
        """Get the current loop state."""
        return self.loop_stack[-1] if self.loop_stack else None

    def to_template_context(self) -> dict[str, Any]:
        """
        Build the template resolution context.

        Provides variables like:
        - {{trigger.alert.severity}}
        - {{steps.step_1.output.body}}
        - {{variables.my_var}}
        - {{loop.item}}
        - {{loop.index}}
        """
        context = {
            "trigger": self.trigger_data,
            "steps": {k: v.output for k, v in self.steps.items()},
            "variables": self.variables,
        }

        if self.current_loop:
            context["loop"] = {
                "item": self.current_loop.current_item,
                "index": self.current_loop.current_index,
                "total": len(self.current_loop.items),
            }

        return context

    def to_dict(self) -> dict[str, Any]:
        """Serialize context for storage."""
        return {
            "execution_id": str(self.execution_id),
            "workflow_id": str(self.workflow_id),
            "trigger_data": self.trigger_data,
            "variables": self.variables,
            "steps": {
                k: {
                    "node_key": v.node_key,
                    "status": v.status,
                    "output": v.output,
                    "error": v.error,
                    "duration_ms": v.duration_ms,
                }
                for k, v in self.steps.items()
            },
            "started_at": self.started_at.isoformat(),
        }
