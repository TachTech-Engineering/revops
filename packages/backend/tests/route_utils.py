"""
Helpers to enumerate the app's effective HTTP routes.

FastAPI >= 0.14x no longer flattens include_router() into app.routes; instead
app.routes contains lazy ``_IncludedRouter`` entries whose
``effective_candidates()`` yield fully-prefixed route contexts (duck-typed
here rather than imported, so older flat layouts keep working). Walk order
matches starlette's first-full-match dispatch order, so the first regex+method
match found by ``resolve`` is the route that would actually handle a request.
"""
from dataclasses import dataclass
from typing import Any, Iterator, Optional


@dataclass(frozen=True)
class HttpRoute:
    path: str
    method: str
    endpoint: Any
    path_regex: Any


def iter_http_routes(app) -> Iterator[HttpRoute]:
    """Yield every effective HTTP route (path template, single method).

    Websocket routes and mounts are skipped: they have no ``methods``.
    HEAD/OPTIONS are skipped as auto-generated companions.
    """
    yield from _walk(app.routes)


def _walk(routes) -> Iterator[HttpRoute]:
    for route in routes:
        if hasattr(route, "effective_candidates"):
            # fastapi _IncludedRouter: recurse into its effective candidates,
            # which preserve registration order and carry full prefixes.
            yield from _walk(route.effective_candidates())
            continue
        path = getattr(route, "path", "") or ""
        methods = getattr(route, "methods", None) or ()
        path_regex = getattr(route, "path_regex", None)
        endpoint = getattr(route, "endpoint", None)
        if not path or not methods or path_regex is None:
            continue  # websocket routes, mounts, non-http contexts
        for method in sorted(methods):
            if method in ("HEAD", "OPTIONS"):
                continue
            yield HttpRoute(
                path=path, method=method, endpoint=endpoint, path_regex=path_regex
            )


def resolve(app, path: str, method: str) -> Optional[HttpRoute]:
    """First route whose regex + method fully match, mirroring dispatch."""
    for route in iter_http_routes(app):
        if route.method == method and route.path_regex.match(path):
            return route
    return None
