"""
Set Variable Node Executor

Sets workflow-level variables for use in subsequent steps.
"""

from typing import Any

from app.services.workflow_engine.nodes.base import NodeExecutor, NodeResult
from app.services.workflow_engine.context import ExecutionContext
from app.services.workflow_engine.templating import TemplateResolver


class SetVariableExecutor(NodeExecutor):
    """
    Sets one or more workflow variables.

    Config:
    - variables: Dict of variable_name -> value (can be templates)
    """

    async def execute(self, context: ExecutionContext) -> NodeResult:
        """Set workflow variables."""
        try:
            variables = self.config.get("variables", {})

            if not variables:
                return NodeResult(
                    success=True,
                    output={"set_variables": []},
                    next_handle="default",
                )

            resolver = TemplateResolver(context.to_template_context())
            set_vars = []

            for name, value in variables.items():
                # Resolve template values
                resolved_value = resolver.resolve(value)
                context.set_variable(name, resolved_value)
                set_vars.append(name)

            return NodeResult(
                success=True,
                output={
                    "set_variables": set_vars,
                    "variables": {name: context.get_variable(name) for name in set_vars},
                },
                next_handle="default",
            )

        except Exception as e:
            return NodeResult(
                success=False,
                error=f"Set variable error: {str(e)}",
            )
