"""
main.py — FastAPI blast radius mapper API.

Endpoints:
  GET  /agents                          list all agents
  GET  /blast-radius/{agent_id}         full blast radius report
  GET  /attack-paths/{agent_id}/{rid}   shortest attack paths to a resource
  POST /what-if                         hypothetical scope addition
  GET  /graph                           full graph for vis.js
  POST /seed                            (re)seed the graph with demo data

Run locally:
    uvicorn main:app --reload --port 8000

Then open ui/index.html in your browser.
"""
import logging
import time

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from neo4j.exceptions import ServiceUnavailable

import graph
from models import (
    AgentNode, AttackPathReport, BlastRadiusReport,
    VisGraph, WhatIfReport, WhatIfRequest,
)
from seeder import seed_graph

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("api")

app = FastAPI(
    title="Blast Radius Mapper",
    description="Visualize and analyze the attack surface of AI agent deployments",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Startup ───────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    """Wait for Neo4j to be ready, then seed if empty."""
    for attempt in range(30):
        try:
            agents = graph.list_agents()
            if not agents:
                logger.info("Graph is empty — seeding demo data...")
                seed_graph()
            else:
                logger.info(f"Graph already seeded with {len(agents)} agents.")
            return
        except ServiceUnavailable:
            logger.info(f"Neo4j not ready yet (attempt {attempt + 1}/30) — waiting...")
            time.sleep(2)
    logger.error("Could not connect to Neo4j after 30 attempts.")


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/agents", response_model=list[AgentNode])
def list_agents():
    """List all agents in the graph."""
    return graph.list_agents()


@app.get("/blast-radius/{agent_id}", response_model=BlastRadiusReport)
def blast_radius(agent_id: str):
    """
    Full blast radius analysis for an agent.

    Returns direct resources (agent → tool → scope → resource)
    and lateral resources (reachable via CAN_REACH traversal).
    """
    report = graph.get_blast_radius(agent_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found")
    return report


@app.get("/attack-paths/{agent_id}/{resource_id:path}", response_model=AttackPathReport)
def attack_paths(agent_id: str, resource_id: str):
    """
    Find the shortest attack paths from an agent to a specific resource.
    resource_id should be URL-encoded if it contains slashes (e.g. s3%3A%2F%2Fcustomer-pii).
    """
    return graph.get_attack_paths(agent_id, resource_id)


@app.post("/what-if", response_model=WhatIfReport)
def what_if(req: WhatIfRequest):
    """
    Hypothetical analysis: if we add a new scope to an agent,
    how many new resources become reachable and by how much does risk increase?
    """
    agent = graph.get_agent(req.agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent '{req.agent_id}' not found")
    return graph.what_if_add_scope(req.agent_id, req.add_scope)


@app.get("/graph", response_model=VisGraph)
def full_graph():
    """
    Return the entire graph in vis.js format for frontend visualization.
    Nodes: agents (purple), tools (teal), scopes (amber), resources (color by sensitivity).
    Edges: solid = permission grants, dashed = lateral movement.
    """
    return graph.get_full_graph()


@app.post("/seed")
def reseed():
    """Reset and reseed the graph with demo data. Useful for demos."""
    try:
        seed_graph()
        return {"status": "ok", "message": "Graph reseeded with demo infrastructure topology."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/health")
def health():
    return {"status": "ok"}
