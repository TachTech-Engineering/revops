"""
Transform Node Executor

Transforms and reshapes data during workflow execution.
"""

import json
from typing import Any

from app.services.workflow_engine.nodes.base import NodeExecutor, NodeResult
from app.services.workflow_engine.context import ExecutionContext
from app.services.workflow_engine.templating import TemplateResolver


class TransformExecutor(NodeExecutor):
    """
    Transforms input data to a new shape.

    Config:
    - mode: "template" | "jq" | "extract" | "merge"
    - template: Output template (for template mode)
    - expression: JQ expression (for jq mode)
    - field: Field path to extract (for extract mode)
    - sources: List of step keys to merge (for merge mode)
    """

    async def execute(self, context: ExecutionContext) -> NodeResult:
        """Execute data transformation."""
        try:
            mode = self.config.get("mode", "template")

            if mode == "template":
                result = self._transform_template(context)
            elif mode == "extract":
                result = self._transform_extract(context)
            elif mode == "merge":
                result = self._transform_merge(context)
            elif mode == "map":
                result = self._transform_map(context)
            else:
                return NodeResult(
                    success=False,
                    error=f"Unknown transform mode: {mode}",
                )

            return NodeResult(
                success=True,
                output={"result": result},
                next_handle="default",
            )

        except Exception as e:
            return NodeResult(
                success=False,
                error=f"Transform error: {str(e)}",
            )

    def _transform_template(self, context: ExecutionContext) -> Any:
        """Transform using a template."""
        template = self.config.get("template", {})
        resolver = TemplateResolver(context.to_template_context())
        return resolver.resolve(template)

    def _transform_extract(self, context: ExecutionContext) -> Any:
        """Extract a specific field from context."""
        field_path = self.config.get("field", "")
        if not field_path:
            return None

        parts = field_path.split(".")
        value = context.to_template_context()

        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            elif isinstance(value, list):
                try:
                    value = value[int(part)]
                except (ValueError, IndexError):
                    return None
            else:
                return None
            if value is None:
                return None

        return value

    def _transform_merge(self, context: ExecutionContext) -> dict:
        """Merge outputs from multiple steps."""
        sources = self.config.get("sources", [])
        result = {}

        for source in sources:
            if isinstance(source, str):
                # Source is a step key
                step_output = context.get_step_output(source)
                if step_output and isinstance(step_output, dict):
                    result.update(step_output)
            elif isinstance(source, dict):
                # Source is a key-value mapping
                key = source.get("key")
                value_path = source.get("value")
                if key and value_path:
                    resolver = TemplateResolver(context.to_template_context())
                    result[key] = resolver.resolve(f"{{{{{value_path}}}}}")

        return result

    def _transform_map(self, context: ExecutionContext) -> list:
        """Map a transformation over a list."""
        source_field = self.config.get("source", "")
        item_template = self.config.get("item_template", {})

        # Get source list
        resolver = TemplateResolver(context.to_template_context())
        source_list = resolver.resolve(f"{{{{{source_field}}}}}")

        if not isinstance(source_list, list):
            return []

        # Transform each item
        results = []
        for index, item in enumerate(source_list):
            # Create item context
            item_context = context.to_template_context()
            item_context["item"] = item
            item_context["index"] = index

            item_resolver = TemplateResolver(item_context)
            results.append(item_resolver.resolve(item_template))

        return results
