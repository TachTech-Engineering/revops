#!/usr/bin/env python3
"""
Cartography -> RevOps asset inventory sync.

Reads cloud assets and relationships from a Cartography Neo4j database and
bulk-imports them into RevOps via POST /api/v1/assets/import. Run it where
Cartography runs (cron after each Cartography sync); RevOps itself never
needs a Neo4j connection.

Requires: pip install neo4j requests

Environment:
  NEO4J_URI        bolt://localhost:7687
  NEO4J_USER       neo4j
  NEO4J_PASSWORD   ...
  REVOPS_URL       https://revops.example.com
  REVOPS_TOKEN     RevOps JWT (analyst role or above)

The queries cover the highest-value Cartography node types for attack-path
evaluation: EC2 instances (with exposure), S3 buckets, RDS instances, IAM
users/roles, and AWS accounts. Extend NODE_QUERIES for more.
"""

import os
import sys

import requests

try:
    from neo4j import GraphDatabase
except ImportError:
    print("pip install neo4j requests", file=sys.stderr)
    sys.exit(1)

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "")
REVOPS_URL = os.environ.get("REVOPS_URL", "").rstrip("/")
REVOPS_TOKEN = os.environ.get("REVOPS_TOKEN", "")

BATCH_SIZE = 1000

# (cypher, mapper) pairs; each mapper returns an asset-import dict
NODE_QUERIES = [
    (
        """
        MATCH (a:AWSAccount) RETURN a.id AS id, a.name AS name
        """,
        lambda r: {
            "external_id": f"account:aws:{r['id']}",
            "asset_type": "cloud_account",
            "name": r["name"] or r["id"],
            "provider": "aws",
            "account_id": r["id"],
        },
    ),
    (
        """
        MATCH (i:EC2Instance)
        OPTIONAL MATCH (i)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
                <-[:MEMBER_OF_EC2_SECURITY_GROUP]-(rule:IpPermissionInbound)
                <-[:MEMBER_OF_IP_RULE]-(range:IpRange {range: '0.0.0.0/0'})
        RETURN i.id AS id, i.instanceid AS instance_id, i.region AS region,
               i.publicipaddress AS public_ip,
               count(range) > 0 AS open_to_world
        """,
        lambda r: {
            "external_id": r["id"],
            "asset_type": "vm_instance",
            "name": r["instance_id"] or r["id"],
            "provider": "aws",
            "region": r["region"],
            "internet_exposed": bool(r["public_ip"]) and bool(r["open_to_world"]),
            "attrs": {"public_ip": r["public_ip"]},
        },
    ),
    (
        """
        MATCH (b:S3Bucket)
        RETURN b.id AS id, b.name AS name, b.region AS region,
               b.anonymous_access AS anonymous_access
        """,
        lambda r: {
            "external_id": r["id"],
            "asset_type": "storage_bucket",
            "name": r["name"] or r["id"],
            "provider": "aws",
            "region": r["region"],
            "internet_exposed": bool(r["anonymous_access"]),
        },
    ),
    (
        """
        MATCH (d:RDSInstance)
        RETURN d.id AS id, d.db_instance_identifier AS name, d.region AS region,
               d.publicly_accessible AS public
        """,
        lambda r: {
            "external_id": r["id"],
            "asset_type": "database",
            "name": r["name"] or r["id"],
            "provider": "aws",
            "region": r["region"],
            "internet_exposed": bool(r["public"]),
        },
    ),
    (
        """
        MATCH (u:AWSUser) RETURN u.arn AS arn, u.name AS name
        """,
        lambda r: {
            "external_id": r["arn"],
            "asset_type": "iam_identity",
            "name": r["name"] or r["arn"],
            "provider": "aws",
        },
    ),
    (
        """
        MATCH (role:AWSRole) RETURN role.arn AS arn, role.name AS name
        """,
        lambda r: {
            "external_id": r["arn"],
            "asset_type": "iam_role",
            "name": r["name"] or r["arn"],
            "provider": "aws",
        },
    ),
]

RELATIONSHIP_QUERIES = [
    (
        """
        MATCH (a:AWSAccount)-[:RESOURCE]->(i:EC2Instance)
        RETURN a.id AS account, i.id AS resource
        """,
        lambda r: {
            "source_external_id": f"account:aws:{r['account']}",
            "target_external_id": r["resource"],
            "relationship_type": "contains",
        },
    ),
    (
        """
        MATCH (a:AWSAccount)-[:RESOURCE]->(b:S3Bucket)
        RETURN a.id AS account, b.id AS resource
        """,
        lambda r: {
            "source_external_id": f"account:aws:{r['account']}",
            "target_external_id": r["resource"],
            "relationship_type": "contains",
        },
    ),
    (
        """
        MATCH (i:EC2Instance)-[:INSTANCE_PROFILE]->(:AWSInstanceProfile)
              -[:ASSOCIATED_WITH]->(role:AWSRole)
        RETURN i.id AS instance, role.arn AS role
        """,
        lambda r: {
            "source_external_id": r["instance"],
            "target_external_id": r["role"],
            "relationship_type": "assumes_role",
        },
    ),
]


def main() -> int:
    if not REVOPS_URL or not REVOPS_TOKEN:
        print("Set REVOPS_URL and REVOPS_TOKEN", file=sys.stderr)
        return 1

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    assets, relationships = [], []
    with driver.session() as session:
        for cypher, mapper in NODE_QUERIES:
            for record in session.run(cypher):
                item = mapper(record)
                if item.get("external_id"):
                    assets.append(item)
        for cypher, mapper in RELATIONSHIP_QUERIES:
            for record in session.run(cypher):
                relationships.append(mapper(record))
    driver.close()

    print(f"Collected {len(assets)} assets, {len(relationships)} relationships")

    headers = {"Authorization": f"Bearer {REVOPS_TOKEN}"}
    total_imported = 0
    for start in range(0, max(len(assets), 1), BATCH_SIZE):
        batch_assets = assets[start : start + BATCH_SIZE]
        # Send relationships with the final batch so both endpoints exist
        batch_rels = relationships if start + BATCH_SIZE >= len(assets) else []
        response = requests.post(
            f"{REVOPS_URL}/api/v1/assets/import",
            json={
                "source": "cartography",
                "assets": batch_assets,
                "relationships": batch_rels,
            },
            headers=headers,
            timeout=120,
        )
        response.raise_for_status()
        body = response.json()
        total_imported += body.get("assets_imported", 0)
        for error in body.get("errors", []):
            print(f"  warning: {error}", file=sys.stderr)

    print(f"Imported {total_imported} assets into RevOps")
    return 0


if __name__ == "__main__":
    sys.exit(main())
