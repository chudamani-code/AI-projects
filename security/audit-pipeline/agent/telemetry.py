"""
telemetry.py — OpenTelemetry tracer and structured logger initialisation.

Sends:
  Traces → OTel Collector (gRPC :4317) → Tempo → Grafana
  Logs   → OTel Collector (gRPC :4317) → Loki  → Grafana

Every trace has spans for:
  agent_task          (root span, covers the full task lifecycle)
  ├── llm_call        (one per Anthropic API call)
  ├── tool_call       (one per tool execution)
  └── policy_check    (one per OPA evaluation)

Span attributes follow the OpenTelemetry semantic conventions where possible,
with custom attributes prefixed `agsec.*`.
"""
import logging
import os

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# Graceful degradation: if the OTLP exporter isn't installed, fall back to
# a no-op provider so the agent runs without the full OTel stack.
try:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    _OTLP_AVAILABLE = True
except ImportError:
    _OTLP_AVAILABLE = False

try:
    from opentelemetry._logs import set_logger_provider
    from opentelemetry.sdk._logs import LoggerProvider
    from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
    from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
    from opentelemetry.instrumentation.logging import LoggingInstrumentor
    _LOGS_AVAILABLE = True
except ImportError:
    _LOGS_AVAILABLE = False

OTEL_ENDPOINT = os.getenv("OTEL_ENDPOINT", "http://localhost:4317")
SERVICE_NAME  = os.getenv("SERVICE_NAME", "ai-agent")

_tracer: trace.Tracer | None = None


def init_telemetry(agent_id: str) -> trace.Tracer:
    """
    Initialise the OTel tracer and log provider for this agent process.
    Call once at startup. Returns the tracer to use for spans.
    """
    global _tracer

    resource = Resource.create({
        "service.name": SERVICE_NAME,
        "agent_id": agent_id,
        "deployment.environment": os.getenv("ENVIRONMENT", "local"),
    })

    # ── Traces ────────────────────────────────────────────────────────────────
    provider = TracerProvider(resource=resource)

    if _OTLP_AVAILABLE:
        exporter = OTLPSpanExporter(endpoint=OTEL_ENDPOINT, insecure=True)
        provider.add_span_processor(BatchSpanProcessor(exporter))

    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer(f"agsec.{agent_id}")

    # ── Logs ──────────────────────────────────────────────────────────────────
    if _LOGS_AVAILABLE:
        log_provider = LoggerProvider(resource=resource)
        if _OTLP_AVAILABLE:
            log_exporter = OTLPLogExporter(endpoint=OTEL_ENDPOINT, insecure=True)
            log_provider.add_log_record_processor(BatchLogRecordProcessor(log_exporter))
        set_logger_provider(log_provider)
        LoggingInstrumentor().instrument(set_logging_format=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    return _tracer


def get_tracer() -> trace.Tracer:
    global _tracer
    if _tracer is None:
        _tracer = trace.get_tracer("agsec.default")
    return _tracer
