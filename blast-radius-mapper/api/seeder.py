"""
seeder.py — seeds Neo4j with a realistic cloud infrastructure topology.

Topology models a typical AWS environment:

  Agents:
    agent-reader      LOW trust  — can only list/read S3
    agent-processor   MED trust  — can read/write S3, invoke Lambda
    agent-admin       HIGH trust — all of the above + secrets, EC2, assume-role

  Resources (with sensitivity levels):
    s3://logs-archive          LOW       — application logs
    s3://ml-models             HIGH      — proprietary model weights
    s3://customer-pii          CRITICAL  — PII data store
    lambda://data-processor    HIGH      — processes customer records
    rds://prod-db              CRITICAL  — production database
    secrets://db-credentials   CRITICAL  — RDS connection string + password
    secrets://api-keys         HIGH      — third-party API credentials
    ec2://bastion              HIGH      — SSH jump host
    ec2://ml-worker            HIGH      — GPU training instance

  Lateral movement edges:
    lambda://data-processor  --[env_vars]-->      secrets://db-credentials
    ec2://bastion            --[instance_profile]--> s3://customer-pii
    ec2://ml-worker          --[imds]-->           secrets://db-credentials
    ec2://ml-worker          --[mounted_volume]--> s3://ml-models
    rds://prod-db            --[trusted_link]-->   secrets://api-keys

  This creates differentiated blast radii:
    agent-reader     → 1 direct resource, 0 lateral  (risk: LOW)
    agent-processor  → 4 direct, 2 lateral via Lambda (risk: HIGH)
    agent-admin      → 9 direct, full lateral reach   (risk: CRITICAL)

Run once:
    python seeder.py
Or call seed_graph() from main.py startup.
"""
import logging
from graph import get_driver

logger = logging.getLogger(__name__)


AGENTS = [
    {
        "id": "agent-reader",
        "name": "agent-reader",
        "trust_level": "LOW",
        "description": "Read-only reporting agent. Lists and reads S3 logs.",
    },
    {
        "id": "agent-processor",
        "name": "agent-processor",
        "trust_level": "MEDIUM",
        "description": "Data pipeline agent. Reads source data, invokes Lambda, writes results.",
    },
    {
        "id": "agent-admin",
        "name": "agent-admin",
        "trust_level": "HIGH",
        "description": "Infrastructure management agent. Broad access including secrets and IAM.",
    },
]

# name, scope, description, agents_with_this_tool
TOOLS = [
    ("list_s3_buckets",    "scope:s3:list",               "List S3 bucket names",                       ["agent-reader", "agent-processor", "agent-admin"]),
    ("read_s3_object",     "scope:s3:read",               "Read objects from S3 buckets",               ["agent-reader", "agent-processor", "agent-admin"]),
    ("write_s3_object",    "scope:s3:write",              "Write objects to S3 buckets",                ["agent-processor", "agent-admin"]),
    ("invoke_lambda",      "scope:lambda:invoke",         "Invoke Lambda functions",                    ["agent-processor", "agent-admin"]),
    ("describe_ec2",       "scope:ec2:describe",          "Read EC2 instance metadata",                 ["agent-admin"]),
    ("read_secrets",       "scope:secretsmanager:read",   "Read secrets from Secrets Manager",          ["agent-admin"]),
    ("assume_iam_role",    "scope:iam:assume",            "Assume IAM roles (privilege escalation path)", ["agent-admin"]),
    ("query_rds",          "scope:rds:query",             "Execute SQL queries against RDS",            ["agent-admin"]),
]

# id, name, type, sensitivity, description
RESOURCES = [
    ("s3://logs-archive",        "logs-archive",        "S3Bucket",      "LOW",      "Application log archive. Publicly accessible patterns."),
    ("s3://ml-models",           "ml-models",           "S3Bucket",      "HIGH",     "Proprietary ML model weights. IP exfiltration risk."),
    ("s3://customer-pii",        "customer-pii",        "S3Bucket",      "CRITICAL", "Customer PII: names, emails, addresses. GDPR scope."),
    ("lambda://data-processor",  "data-processor",      "Lambda",        "HIGH",     "Processes customer records. Has DB credentials in env vars."),
    ("rds://prod-db",            "prod-db",             "Database",      "CRITICAL", "Production RDS PostgreSQL. All customer records."),
    ("secrets://db-credentials", "db-credentials",      "SecretStore",   "CRITICAL", "RDS connection string and master password."),
    ("secrets://api-keys",       "api-keys",            "SecretStore",   "HIGH",     "Third-party API keys: Stripe, Twilio, SendGrid."),
    ("ec2://bastion",            "bastion",             "EC2",           "HIGH",     "SSH jump host. Instance profile can read customer-pii bucket."),
    ("ec2://ml-worker",          "ml-worker",           "EC2",           "HIGH",     "GPU training instance. Mounts ml-models volume, IMDS enabled."),
]

# scope_name, resource_id, access_type
SCOPE_GRANTS = [
    ("scope:s3:list",             "s3://logs-archive",        "list"),
    ("scope:s3:read",             "s3://logs-archive",        "read"),
    ("scope:s3:read",             "s3://ml-models",           "read"),
    ("scope:s3:read",             "s3://customer-pii",        "read"),
    ("scope:s3:write",            "s3://logs-archive",        "write"),
    ("scope:s3:write",            "s3://ml-models",           "write"),
    ("scope:s3:write",            "s3://customer-pii",        "write"),
    ("scope:lambda:invoke",       "lambda://data-processor",  "invoke"),
    ("scope:ec2:describe",        "ec2://bastion",            "read"),
    ("scope:ec2:describe",        "ec2://ml-worker",          "read"),
    ("scope:secretsmanager:read", "secrets://db-credentials", "read"),
    ("scope:secretsmanager:read", "secrets://api-keys",       "read"),
    ("scope:iam:assume",          "ec2://bastion",            "assume"),
    ("scope:iam:assume",          "ec2://ml-worker",          "assume"),
    ("scope:rds:query",           "rds://prod-db",            "query"),
]

# from_resource_id, to_resource_id, method, description
LATERAL_EDGES = [
    (
        "lambda://data-processor",
        "secrets://db-credentials",
        "env_vars",
        "Lambda function has DB_PASSWORD set as an environment variable",
    ),
    (
        "ec2://bastion",
        "s3://customer-pii",
        "instance_profile",
        "Bastion instance profile has s3:GetObject on customer-pii bucket",
    ),
    (
        "ec2://ml-worker",
        "secrets://db-credentials",
        "imds",
        "IMDS v1 enabled; instance profile can fetch db-credentials secret",
    ),
    (
        "ec2://ml-worker",
        "s3://ml-models",
        "mounted_volume",
        "EBS volume with ml-models data is mounted at /models",
    ),
    (
        "rds://prod-db",
        "secrets://api-keys",
        "stored_procedure",
        "A stored procedure with SECURITY DEFINER reads api-keys and caches results",
    ),
]


def seed_graph() -> None:
    driver = get_driver()
    with driver.session() as s:
        # Clear existing data
        s.run("MATCH (n) DETACH DELETE n")
        logger.info("Cleared existing graph data")

        # Create constraints (idempotent)
        s.run("CREATE CONSTRAINT agent_id IF NOT EXISTS FOR (a:Agent) REQUIRE a.id IS UNIQUE")
        s.run("CREATE CONSTRAINT resource_id IF NOT EXISTS FOR (r:Resource) REQUIRE r.id IS UNIQUE")
        s.run("CREATE CONSTRAINT scope_name IF NOT EXISTS FOR (s:Scope) REQUIRE s.name IS UNIQUE")
        s.run("CREATE CONSTRAINT tool_name IF NOT EXISTS FOR (t:Tool) REQUIRE t.name IS UNIQUE")

        # Agents
        for a in AGENTS:
            s.run("""
                MERGE (a:Agent {id: $id})
                SET a.name = $name, a.trust_level = $trust_level, a.description = $description
            """, **a)
        logger.info(f"Created {len(AGENTS)} agents")

        # Tools + Scopes + HAS_TOOL + REQUIRES_SCOPE
        for name, scope, description, agent_ids in TOOLS:
            s.run("""
                MERGE (t:Tool {name: $name})
                SET t.scope = $scope, t.description = $description
                MERGE (sc:Scope {name: $scope})
                MERGE (t)-[:REQUIRES_SCOPE]->(sc)
            """, name=name, scope=scope, description=description)

            for agent_id in agent_ids:
                s.run("""
                    MATCH (a:Agent {id: $agent_id})
                    MATCH (t:Tool {name: $tool_name})
                    MERGE (a)-[:HAS_TOOL]->(t)
                """, agent_id=agent_id, tool_name=name)
        logger.info(f"Created {len(TOOLS)} tools")

        # Resources
        for res_id, name, res_type, sensitivity, description in RESOURCES:
            s.run("""
                MERGE (r:Resource {id: $id})
                SET r.name = $name, r.type = $type,
                    r.sensitivity = $sensitivity, r.description = $description
            """, id=res_id, name=name, type=res_type, sensitivity=sensitivity, description=description)
        logger.info(f"Created {len(RESOURCES)} resources")

        # Scope → Resource grants
        for scope_name, resource_id, access_type in SCOPE_GRANTS:
            s.run("""
                MATCH (sc:Scope {name: $scope_name})
                MATCH (r:Resource {id: $resource_id})
                MERGE (sc)-[:GRANTS_ACCESS_TO {access_type: $access_type}]->(r)
            """, scope_name=scope_name, resource_id=resource_id, access_type=access_type)
        logger.info(f"Created {len(SCOPE_GRANTS)} scope grants")

        # Lateral movement edges
        for from_id, to_id, method, description in LATERAL_EDGES:
            s.run("""
                MATCH (r1:Resource {id: $from_id})
                MATCH (r2:Resource {id: $to_id})
                MERGE (r1)-[:CAN_REACH {method: $method, description: $description}]->(r2)
            """, from_id=from_id, to_id=to_id, method=method, description=description)
        logger.info(f"Created {len(LATERAL_EDGES)} lateral movement edges")

    logger.info("Graph seeded successfully")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    seed_graph()
    print("Done — graph seeded.")
