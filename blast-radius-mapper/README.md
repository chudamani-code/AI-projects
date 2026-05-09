# Blast Radius Mapper — AI Agent Security

A security analysis tool that models the reachable attack surface of AI agents
as a graph in Neo4j, then lets you explore blast radius, lateral movement paths,
and "what-if" permission scenarios through an interactive web UI.

Built as an interview portfolio project — demonstrates architect-level thinking
about AI agent security.

---

## What it shows

```
agent-reader  (LOW trust)     → 1 resource directly, 0 lateral
agent-processor (MEDIUM trust) → 4 resources directly, 2 via lateral movement
agent-admin   (HIGH trust)    → 9 resources directly, full lateral reach
```

The graph models real AWS patterns:
- An agent with `scope:lambda:invoke` can invoke a Lambda function
- That Lambda has `DB_PASSWORD` in its env vars → **lateral reach to db-credentials**
- An agent with `scope:ec2:describe` can read EC2 metadata
- That EC2 instance has an instance profile → **lateral reach to customer-pii bucket**

---

## Quick start

### Option A: Docker Compose (recommended)

```bash
docker compose up --build
```

- API: http://localhost:8000/docs
- Neo4j Browser: http://localhost:7474 (neo4j / blastradius)

Then open `ui/index.html` in your browser.

### Option B: Local (no Docker)

**1. Start Neo4j**
```bash
# Mac
brew install neo4j
neo4j start
# Default: bolt://localhost:7687, user: neo4j, password: neo4j
# Change password in Neo4j Browser first run, then update NEO4J_PASSWORD below
```

**2. Start the API**
```bash
cd api
pip install -r requirements.txt
export NEO4J_PASSWORD=your_password
uvicorn main:app --reload --port 8000
```

**3. Open the UI**
```
Open ui/index.html in your browser
```

---

## API endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/agents` | List all agents |
| GET | `/blast-radius/{agent_id}` | Full blast radius report |
| GET | `/attack-paths/{agent_id}/{resource_id}` | Shortest attack paths |
| POST | `/what-if` | Hypothetical scope addition |
| GET | `/graph` | Full graph in vis.js format |
| POST | `/seed` | Reset and reseed demo data |

---

## Cypher queries for the Neo4j Browser

These are interview-ready queries to demonstrate directly:

```cypher
-- Full blast radius for an agent
MATCH (a:Agent {id: 'agent-processor'})-[:HAS_TOOL]->(t:Tool)
      -[:REQUIRES_SCOPE]->(s:Scope)-[:GRANTS_ACCESS_TO]->(r:Resource)
RETURN a, t, s, r

-- Lateral movement paths
MATCH (a:Agent {id: 'agent-processor'})-[:HAS_TOOL]->(t:Tool)
      -[:REQUIRES_SCOPE]->(s:Scope)-[:GRANTS_ACCESS_TO]->(seed:Resource)
MATCH path = (seed)-[:CAN_REACH*1..4]->(lateral:Resource)
RETURN path

-- All agents that can reach a CRITICAL resource (any path)
MATCH (a:Agent)-[:HAS_TOOL|REQUIRES_SCOPE|GRANTS_ACCESS_TO|CAN_REACH*]->(r:Resource)
WHERE r.sensitivity = 'CRITICAL'
RETURN DISTINCT a.id, a.trust_level, collect(DISTINCT r.name) AS critical_resources

-- What permission lets agent-reader reach the most new resources?
MATCH (s:Scope)-[:GRANTS_ACCESS_TO]->(r:Resource)
WHERE NOT EXISTS {
  MATCH (a:Agent {id:'agent-reader'})-[:HAS_TOOL]->(t)-[:REQUIRES_SCOPE]->(s)
}
RETURN s.name, count(r) AS new_resources
ORDER BY new_resources DESC
```

---

## Graph schema

```
(Agent)-[:HAS_TOOL]->(Tool)-[:REQUIRES_SCOPE]->(Scope)
(Scope)-[:GRANTS_ACCESS_TO {access_type}]->(Resource)
(Resource)-[:CAN_REACH {method, description}]->(Resource)
```

Node properties:
- **Agent**: id, name, trust_level (LOW|MEDIUM|HIGH), description
- **Tool**: name, scope, description
- **Scope**: name (e.g. "scope:s3:read")
- **Resource**: id, name, type, sensitivity (LOW|MEDIUM|HIGH|CRITICAL), description

---

## Extending the project

- **Add your real infrastructure**: Replace `seeder.py` with a script that reads
  your AWS IAM policies, CloudTrail data, or Terraform state files and builds the
  graph from actual permissions.
- **Add time dimension**: Record `granted_at` on HAS_TOOL edges and flag
  permissions older than 90 days as stale.
- **Alert on blast radius growth**: Run the blast radius query in CI/CD. If
  `risk_score` increases by more than 10 points, block the merge.
- **Add Kubernetes**: Model ServiceAccounts, ClusterRoles, and RoleBindings as
  the permission layer instead of IAM.
