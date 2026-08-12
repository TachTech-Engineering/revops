"""Dump the backend's OpenAPI schema to stdout.

Run *inside* the backend image (which has `app` importable), e.g.:

    docker run --rm -i revops-oapi python - < dump_openapi.py > openapi.json

We deliberately import the app and call ``app.openapi()`` rather than booting a
server, so no database / network is required.

Workaround for a latent backend quirk
--------------------------------------
One route declares ``response_model=list["AlertEscalationResponse"]`` -- a
*stringized* forward reference. Under the pinned FastAPI/Pydantic v2 stack the
TypeAdapter built for that annotation loses the module namespace where
``AlertEscalationResponse`` is defined, so ``app.openapi()`` raises
``PydanticUserError: ... is not fully defined``. We resolve the annotation to the
real class on the source route before generation. This only affects schema
generation here; it does not modify backend source. If the backend later drops
the quotes (``response_model=list[AlertEscalationResponse]``) this shim becomes a
no-op and can be removed.
"""

import json
import sys


def _resolve_stringized_response_models() -> None:
    try:
        from app.api.v1 import escalation
    except Exception:  # pragma: no cover - module missing/renamed => nothing to fix
        return

    router = getattr(escalation, "router", None)
    if router is None:
        return

    for route in getattr(router, "routes", []):
        response_model = getattr(route, "response_model", None)
        if response_model is None:
            continue
        rendered = repr(response_model)
        # Only touch annotations that still carry an unresolved string forward ref.
        if "AlertEscalationResponse" in rendered and "'" in rendered:
            route.response_model = list[escalation.AlertEscalationResponse]
            # Force FastAPI to rebuild the response field from the resolved type
            # when the route is (lazily) materialized into the app.
            route.response_field = None


def main() -> int:
    _resolve_stringized_response_models()

    import app.main as main_module

    schema = main_module.app.openapi()
    # Sort keys for a stable, diff-friendly artifact (drift check relies on this).
    json.dump(schema, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
