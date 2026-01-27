"""
Visual Workflow Engine

Tines-like workflow automation engine with support for:
- Multiple trigger types (alert, schedule, webhook, manual)
- Node-based execution (HTTP, conditions, transforms, loops)
- Template variable resolution
- Execution tracking and debugging
"""

from app.services.workflow_engine.engine import WorkflowEngine
from app.services.workflow_engine.context import ExecutionContext
from app.services.workflow_engine.templating import TemplateResolver

__all__ = [
    "WorkflowEngine",
    "ExecutionContext",
    "TemplateResolver",
]
