"""
graph.py — Neo4j connection and all Cypher queries.

Graph schema:

  (Agent)-[:HAS_TOOL]->(Tool)-[:REQUIRES_SCOPE]->(Scope)
  (Scope)-[:GRANTS_ACCESS_TO {access_type}]->(Resource)
  (Resource)-[:CAN_REACH {method, description}]->(Resource)

Node labels:   Agent | Tool | Scope | Resource
Relationship:  HAS_TOOL | REQUIRES_SCOPE | GRANTS_ACCESS_TO | CAN_REACH

All queries are read-only except those in seeder.py.
"""
import os
from contextlib import contextmanager

from neo4j import GraphDatabase, Session
from neo4j.exceptions import ServiceUnavailable

from models import (
    AccessPath, AgentNode, AttackPathReport, AttackStep,
    BlastRadiusReport, LateralPath, ResourceNode, VisEdge, VisGraph, VisNode,
    WhatIfReport,
)

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "blastradius")

_driver = None


def get_driver():
    global _driver
    if _driver is None:
        _driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    return _driver


@contextmanager
def session() -> Session:
    with get_driver().session() as s:
        yield s


# ── Sensitivity scoring ───────────────────────────────────────────────────────

SENSITIVITY_SCORE = {"LOW": 1, "MEDIUM": 5, "HIGH": 15, "CRITICAL": 25}


def compute_risk_score(resources: list[ResourceNode]) -> int:
    raw = sum(SENSITIVITY_SCORE.get(r.sensitivity, 0) for r in resources)
    return min(100, raw)


def _row_to_resource(r) -> ResourceNode:
    return ResourceNode(
        id=r["id"],
        name=r["name"],
        type=r["type"],
        sensitivity=r["sensitivity"],
        description=r["description"],
    )


# ── Agent queries ─────────────────────────────────────────────────────────────

def list_agents() -> list[AgentNode]:
    with session() as s:
        result = s.run("MATCH (a:Agent) RETURN a ORDER BY a.id")
        return [
            AgentNode(
                id=row["a"]["id"],
                name=row["a"]["name"],
                trust_level=row["a"]["trust_level"],
                description=row["a"]["description"],
            )
            for row in result
        ]


def get_agent(agent_id: str) -> AgentNode | None:
    with session() as s:
        result = s.run("MATCH (a:Agent {id: $id}) RETURN a", id=agent_id)
        row = result.single()
        if not row:
            return None
        a = row["a"]
        return AgentNode(id=a["id"], name=a["name"], trust_level=a["trust_level"], description=a["description"])


# ── Blast radius queries ──────────────────────────────────────────────────────

def get_blast_radius(agent_id: str) -> BlastRadiusReport | None:
    agent = get_agent(agent_id)
    if not agent:
        return None

    with session() as s:
        # Direct resources: agent → tool → scope → resource
        direct_rows = s.run("""
            MATCH (a:Agent {id: $agent_id})-[:HAS_TOOL]->(t:Tool)
                  -[:REQUIRES_SCOPE]->(sc:Scope)
                  -[g:GRANTS_ACCESS_TO]->(r:Resource)
            RETURN DISTINCT
                t.name       AS tool_name,
                sc.name      AS scope_name,
                g.access_type AS access_type,
                r
            ORDER BY r.sensitivity DESC
        """, agent_id=agent_id)

        access_paths: list[AccessPath] = []
        direct_seen: dict[str, ResourceNode] = {}

        for row in direct_rows:
            res = _row_to_resource(row["r"])
            direct_seen[res.id] = res
            access_paths.append(AccessPath(
                tool_name=row["tool_name"],
                scope_name=row["scope_name"],
                resource=res,
                access_type=row["access_type"] or "access",
            ))

        direct_resources = list(direct_seen.values())

        # Lateral movement: direct resources → (CAN_REACH)* → more resources
        lateral_rows = s.run("""
            MATCH (a:Agent {id: $agent_id})-[:HAS_TOOL]->(t:Tool)
                  -[:REQUIRES_SCOPE]->(sc:Scope)
                  -[:GRANTS_ACCESS_TO]->(seed:Resource)
            MATCH path = (seed)-[hops:CAN_REACH*1..4]->(lateral:Resource)
            RETURN DISTINCT
                seed                    AS pivot,
                lateral                 AS lateral_resource,
                [h IN hops | h.method]  AS methods,
                length(path)            AS hops
            ORDER BY hops ASC
        """, agent_id=agent_id)

        lateral_seen: dict[str, ResourceNode] = {}
        lateral_paths: list[LateralPath] = []

        for row in lateral_rows:
            pivot = _row_to_resource(row["pivot"])
            lat = _row_to_resource(row["lateral_resource"])
            methods = row["methods"]

            if lat.id not in direct_seen:  # only count genuinely new reach
                lateral_seen[lat.id] = lat

            lateral_paths.append(LateralPath(
                pivot_resource=pivot,
                lateral_resource=lat,
                method=methods[-1] if methods else "unknown",
                hop_count=row["hops"],
            ))

        lateral_resources = list(lateral_seen.values())
        all_resources = direct_resources + lateral_resources

    # Compute sensitivity counts
    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for r in all_resources:
        counts[r.sensitivity] = counts.get(r.sensitivity, 0) + 1

    return BlastRadiusReport(
        agent_id=agent_id,
        agent=agent,
        direct_resources=direct_resources,
        lateral_resources=lateral_resources,
        access_paths=access_paths,
        lateral_paths=lateral_paths,
        total_unique_resources=len(all_resources),
        critical_count=counts["CRITICAL"],
        high_count=counts["HIGH"],
        medium_count=counts["MEDIUM"],
        low_count=counts["LOW"],
        risk_score=compute_risk_score(all_resources),
    )


# ── Attack path query ─────────────────────────────────────────────────────────

def get_attack_paths(agent_id: str, resource_id: str) -> AttackPathReport:
    with session() as s:
        rows = s.run("""
            MATCH path = (a:Agent {id: $agent_id})
                         -[:HAS_TOOL|REQUIRES_SCOPE|GRANTS_ACCESS_TO|CAN_REACH*]->(r:Resource {id: $resource_id})
            RETURN path
            ORDER BY length(path)
            LIMIT 5
        """, agent_id=agent_id, resource_id=resource_id)

        paths: list[list[AttackStep]] = []
        for row in rows:
            path = row["path"]
            steps: list[AttackStep] = []
            nodes = list(path.nodes)
            rels = list(path.relationships)
            for i, node in enumerate(nodes):
                label = list(node.labels)[0]
                node_id = node.get("id") or node.get("name") or str(node.id)
                node_label = node.get("name") or node.get("id") or node_id
                edge_label = rels[i].type if i < len(rels) else ""
                steps.append(AttackStep(
                    node_type=label,
                    node_id=node_id,
                    node_label=node_label,
                    edge_label=edge_label,
                ))
            paths.append(steps)

    shortest = min((len(p) for p in paths), default=0)
    return AttackPathReport(
        agent_id=agent_id,
        target_resource_id=resource_id,
        paths=paths,
        shortest_hop_count=shortest,
    )


# ── What-if analysis ──────────────────────────────────────────────────────────

def what_if_add_scope(agent_id: str, add_scope: str) -> WhatIfReport:
    """
    Hypothetically: if we grant this agent an additional scope,
    what new resources become reachable — directly and via lateral movement?
    """
    with session() as s:
        # Current reachable resource IDs
        current_rows = s.run("""
            MATCH (a:Agent {id: $agent_id})-[:HAS_TOOL]->(t:Tool)
                  -[:REQUIRES_SCOPE]->(sc:Scope)-[:GRANTS_ACCESS_TO]->(r:Resource)
            RETURN DISTINCT r.id AS rid
        """, agent_id=agent_id)
        current_ids = {row["rid"] for row in current_rows}

        # Also get laterally reachable IDs
        lat_rows = s.run("""
            MATCH (a:Agent {id: $agent_id})-[:HAS_TOOL]->(t:Tool)
                  -[:REQUIRES_SCOPE]->(sc:Scope)-[:GRANTS_ACCESS_TO]->(seed:Resource)
            MATCH (seed)-[:CAN_REACH*1..4]->(lat:Resource)
            RETURN DISTINCT lat.id AS rid
        """, agent_id=agent_id)
        for row in lat_rows:
            current_ids.add(row["rid"])

        # Resources the new scope would grant access to
        new_direct_rows = s.run("""
            MATCH (sc:Scope {name: $scope_name})-[:GRANTS_ACCESS_TO]->(r:Resource)
            RETURN DISTINCT r
        """, scope_name=add_scope)

        new_direct: list[ResourceNode] = []
        new_direct_ids: set[str] = set()
        for row in new_direct_rows:
            r = _row_to_resource(row["r"])
            if r.id not in current_ids:
                new_direct.append(r)
                new_direct_ids.add(r.id)

        # Lateral movement from the newly accessible resources
        new_lateral: list[ResourceNode] = []
        if new_direct_ids:
            for rid in new_direct_ids:
                lat_rows2 = s.run("""
                    MATCH path = (seed:Resource {id: $rid})-[:CAN_REACH*1..4]->(lat:Resource)
                    RETURN DISTINCT lat
                """, rid=rid)
                for row in lat_rows2:
                    r = _row_to_resource(row["lat"])
                    if r.id not in current_ids and r.id not in new_direct_ids:
                        new_lateral.append(r)

    all_new = new_direct + new_lateral
    delta = compute_risk_score(all_new)

    return WhatIfReport(
        agent_id=agent_id,
        add_scope=add_scope,
        new_direct_resources=new_direct,
        new_lateral_resources=new_lateral,
        incremental_risk_delta=delta,
        description=(
            f"Adding scope '{add_scope}' to {agent_id} would grant access to "
            f"{len(new_direct)} new direct resources and "
            f"{len(new_lateral)} additional lateral resources. "
            f"Risk score increase: +{delta}."
        ),
    )


# ── Full graph for vis.js ─────────────────────────────────────────────────────

def get_full_graph() -> VisGraph:
    vis_nodes: dict[str, VisNode] = {}
    vis_edges: list[VisEdge] = []

    with session() as s:
        # Agents
        for row in s.run("MATCH (a:Agent) RETURN a"):
            a = row["a"]
            vis_nodes[a["id"]] = VisNode(
                id=a["id"],
                label=a["name"],
                group="agent",
                title=f"<b>{a['name']}</b><br>Trust: {a['trust_level']}<br>{a['description']}",
            )

        # Tools + HAS_TOOL edges
        for row in s.run("""
            MATCH (a:Agent)-[:HAS_TOOL]->(t:Tool) RETURN a.id AS aid, t
        """):
            t = row["t"]
            if t["name"] not in vis_nodes:
                vis_nodes[t["name"]] = VisNode(
                    id=t["name"],
                    label=t["name"],
                    group="tool",
                    title=f"<b>{t['name']}</b><br>Scope: {t['scope']}<br>{t['description']}",
                )
            vis_edges.append(VisEdge(
                from_=row["aid"], to=t["name"], label="HAS_TOOL",
            ))

        # Scopes + REQUIRES_SCOPE edges
        for row in s.run("""
            MATCH (t:Tool)-[:REQUIRES_SCOPE]->(sc:Scope) RETURN t.name AS tname, sc
        """):
            sc = row["sc"]
            if sc["name"] not in vis_nodes:
                vis_nodes[sc["name"]] = VisNode(
                    id=sc["name"],
                    label=sc["name"].replace("scope:", ""),
                    group="scope",
                    title=f"<b>Scope</b><br>{sc['name']}",
                )
            vis_edges.append(VisEdge(
                from_=row["tname"], to=sc["name"], label="REQUIRES_SCOPE",
            ))

        # Resources + GRANTS_ACCESS_TO edges
        for row in s.run("""
            MATCH (sc:Scope)-[g:GRANTS_ACCESS_TO]->(r:Resource) RETURN sc.name AS scname, g, r
        """):
            r = row["r"]
            if r["id"] not in vis_nodes:
                vis_nodes[r["id"]] = VisNode(
                    id=r["id"],
                    label=r["name"],
                    group="resource",
                    sensitivity=r["sensitivity"],
                    title=(
                        f"<b>{r['name']}</b><br>"
                        f"Type: {r['type']}<br>"
                        f"Sensitivity: {r['sensitivity']}<br>"
                        f"{r['description']}"
                    ),
                )
            vis_edges.append(VisEdge(
                from_=row["scname"], to=r["id"],
                label=row["g"].get("access_type", "access"),
            ))

        # CAN_REACH edges (lateral movement — dashed)
        for row in s.run("""
            MATCH (r1:Resource)-[cr:CAN_REACH]->(r2:Resource)
            RETURN r1.id AS from_id, r2.id AS to_id, cr.method AS method
        """):
            vis_edges.append(VisEdge(
                from_=row["from_id"], to=row["to_id"],
                label=row["method"] or "lateral",
                dashes=True,
            ))

    return VisGraph(nodes=list(vis_nodes.values()), edges=vis_edges)
