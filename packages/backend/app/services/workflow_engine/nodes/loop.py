"""
Loop Node Executor

Iterates over a list and executes child nodes for each item.
"""

from app.services.workflow_engine.context import ExecutionContext
from app.services.workflow_engine.nodes.base import NodeExecutor, NodeResult
from app.services.workflow_engine.templating import TemplateResolver


class LoopExecutor(NodeExecutor):
    """
    Iterates over an array and provides loop.item/loop.index context.

    Config:
    - items: Array to iterate over (can be template expression)
    - max_iterations: Maximum number of iterations (default: 100)

    Output handles:
    - loop_item: Executed for each item
    - loop_complete: Executed after all items processed
    """

    async def execute(self, context: ExecutionContext) -> NodeResult:
        """Execute loop logic."""
        try:
            items_config = self.config.get("items", [])
            max_iterations = self.config.get("max_iterations", 100)

            # Resolve items if it's a template
            resolver = TemplateResolver(context.to_template_context())
            items = resolver.resolve(items_config)

            if not isinstance(items, list):
                items = [items] if items is not None else []

            # Limit iterations
            items = items[:max_iterations]

            if not items:
                # No items to iterate
                return NodeResult(
                    success=True,
                    output={
                        "total_items": 0,
                        "completed": True,
                    },
                    next_handle="loop_complete",
                )

            # Check if we're continuing a loop
            current_loop = context.current_loop
            if current_loop and current_loop.items == items:
                # Continue existing loop
                if context.advance_loop():
                    return NodeResult(
                        success=True,
                        output={
                            "index": context.current_loop.current_index,
                            "item": context.current_loop.current_item,
                            "total_items": len(items),
                            "completed": False,
                        },
                        next_handle="loop_item",
                    )
                else:
                    # Loop complete
                    context.pop_loop()
                    return NodeResult(
                        success=True,
                        output={
                            "total_items": len(items),
                            "completed": True,
                        },
                        next_handle="loop_complete",
                    )
            else:
                # Start new loop
                context.push_loop(items)
                return NodeResult(
                    success=True,
                    output={
                        "index": 0,
                        "item": items[0],
                        "total_items": len(items),
                        "completed": False,
                    },
                    next_handle="loop_item",
                )

        except Exception as e:
            return NodeResult(
                success=False,
                error=f"Loop error: {str(e)}",
            )
