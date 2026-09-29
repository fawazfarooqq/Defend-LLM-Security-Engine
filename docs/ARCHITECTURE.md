# Architecture Notes

## Trust boundaries

- User prompt: untrusted.
- Retrieved RAG document: untrusted.
- System policy: trusted application configuration.
- Simulated model output: untrusted until inspected.
- Incident log: application telemetry, not a source of truth for real-world attacks.

## Why the four layers are separate

A single keyword filter is not enough because indirect prompt injection can arrive through retrieved content rather than the user's message. The architecture therefore separates input inspection, context isolation, generation, and output inspection.

## Extension points

- Replace `DefenseEngine._simulate_model()` with a provider adapter.
- Add authentication around configuration endpoints.
- Persist incidents in PostgreSQL or SQLite.
- Add rate limiting and request IDs at the gateway.
- Add structured JSON logging and OpenTelemetry.
- Add a policy engine for tool authorization.
- Add a retrieval scanner for document ingestion.
