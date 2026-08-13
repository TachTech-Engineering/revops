"""Safety gate for LLM-generated SQL.

Two endpoints let a language model write SQL that is then executed against the
application database (`/ai/ask`, `/queries/natural`). The tenant filter in those
prompts is a *soft instruction*, so the model can omit it, or be steered into
emitting another tenant's organization id. Nothing downstream re-checks it.

This module is the server-side check. It never trusts the model:

  * only a single SELECT statement runs -- no DDL/DML, no multi-statement,
    no comment markers that could hide a second statement;
  * set operations (UNION/EXCEPT/INTERSECT) are rejected, because the classic
    bypass is a correctly-filtered first branch UNIONed with an unfiltered one;
  * the query must constrain `organization_id`, and *every* organization_id
    literal it compares against must equal the caller's own organization.

A query that passes still executes with the caller's own org id, so the worst
a non-compliant model can do is fail closed.
"""

from __future__ import annotations

import re
from uuid import UUID

# Statement kinds and constructs that must never reach the database from a
# model-authored query. `;` and comment markers are included because they are
# how a second statement gets smuggled past a single-statement check.
FORBIDDEN_TOKENS = (
    "DROP",
    "DELETE",
    "INSERT",
    "UPDATE",
    "ALTER",
    "CREATE",
    "TRUNCATE",
    "GRANT",
    "REVOKE",
    "EXEC",
    "EXECUTE",
    "MERGE",
    "CALL",
    "COPY",
    "VACUUM",
    "ATTACH",
    "PG_",
    "INFORMATION_SCHEMA",
    "PG_CATALOG",
    "--",
    "/*",
    "*/",
    ";",
)

# Set operations let an attacker append an unfiltered SELECT to a filtered one.
SET_OPERATIONS = ("UNION", "EXCEPT", "INTERSECT")

# `organization_id = 'uuid'`, tolerating whitespace, double quotes, a table
# qualifier, and a ::uuid cast.
_ORG_PREDICATE = re.compile(
    r"""(?:\w+\.)?organization_id\s*=\s*['"]([0-9a-fA-F-]{36})['"](?:::uuid)?""",
    re.IGNORECASE,
)

# Any organization_id comparison at all, including ones binding to a column,
# a parameter, or a subquery rather than a literal.
_ORG_MENTION = re.compile(r"(?:\w+\.)?organization_id\s*(?:=|IN\b)", re.IGNORECASE)


def validate_generated_sql(sql: str, org_id: UUID | str) -> tuple[bool, str]:
    """Return ``(is_safe, error_message)`` for model-generated ``sql``.

    ``org_id`` is the caller's organization, taken from their authenticated
    session -- never from the model's output or the request body.
    """
    if not sql or not sql.strip():
        return False, "Query is empty"

    stripped = sql.strip().rstrip(";").strip()
    upper = stripped.upper()

    if not (upper.startswith("SELECT") or upper.startswith("WITH")):
        return False, "Only SELECT queries are allowed"

    # Re-check for `;` on the original text: a trailing semicolon is fine, an
    # interior one means a second statement.
    if ";" in sql.strip().rstrip(";"):
        return False, "Only a single statement may be executed"

    for token in FORBIDDEN_TOKENS:
        if token == ";":
            continue  # handled above so a trailing semicolon is tolerated
        if token in upper:
            return False, f"Query contains forbidden keyword: {token}"

    for op in SET_OPERATIONS:
        if re.search(rf"\b{op}\b", upper):
            return False, f"Set operations are not allowed ({op})"

    if not _ORG_MENTION.search(stripped):
        return False, "Query must filter on organization_id"

    # The core tenant check: every organization_id literal must be the
    # caller's own. This is what stops a model (or a prompt-injected user)
    # from reading another tenant's rows through a syntactically valid,
    # "correctly filtered" query.
    expected = str(org_id).lower()
    literals = {m.group(1).lower() for m in _ORG_PREDICATE.finditer(stripped)}
    if not literals:
        return False, "Query must compare organization_id to a literal organization id"
    foreign = literals - {expected}
    if foreign:
        return False, "Query references a different organization"

    return True, ""
