# IntelliBron Aman — SIEM Webhook Pipeline (POC) — Progress Log

Status snapshot for resuming Phase 2 / Phase 3. Last updated: 2026-08-25 (Phase 1 complete).

---

## What this is

End-to-end POC for a B2B SaaS data pipeline: Aman DNS security alerts are
normalized into OCSF and pushed to customer SIEMs via webhooks. Strict
separation between the **Control Plane** (dashboard writes config) and the
**Data Plane** (background pipeline reads config, processes the stream).

## Architecture map

```
Control Plane (writes tenant_configs.json)
  mock_dashboard.py   interactive CLI (tenant / SIEM / webhook / token)
  dashboard_app.py    Streamlit UI (:8501) — Configure · Test Run · Stored Config

Data Plane (reads config, processes the stream)
  data_generator.py   synthetic nested-ECS demo stream
  ingest.py           SOURCE-AGNOSTIC normalizer
                        normalize_to_ocsf(raw) -> OCSF DNS Activity (class 4003)
                        iter_export_csv(path)  -> raw docs (sample adapter)
                        * seam documented for future iter_api_stream(endpoint, key)
  orchestrator.py     filter -> enrich -> batch -> deliver (concurrent, retry, DLQ)
  translator.py       per-SIEM envelope/auth (single + batch)
  config_store.py     validated config load/save + stat-based cache
  queue_manager.py    legacy in-memory Splunk retry queue (NOT wired; superseded by
                      orchestrator retry/DLQ) — candidate for removal in Phase 2
  sender.py           legacy Splunk urllib sender (NOT wired) — candidate for removal
```

Data flow per event:

```
raw ECS doc ──► normalize_to_ocsf ──► tenant isolation ──► blocked filter ──►
  severity enrichment ──► per-SIEM envelope ──► batch (array SIEMs) ──►
  concurrent POST (one worker per tenant/SIEM group) ──► retry/backoff ──► DLQ
```

## Phase status

### Phase 0 — Base pipeline (DONE)
- 3-file skeleton (dashboard / generator / orchestrator) + OCSF ingestion from
  the real sample export (`~/Downloads/opensearch_export_2026-08-21.csv`,
  871 events · 100 blocked · 7 subscribers · dns.request).
- Severity map: malicious=Critical, suspicious=High, gambling=Medium,
  advertising=Medium, tracking_telemetry=Low, benign=Low.
- Streamlit UI with custom design system (Inter, indigo/slate, cards, severity dots).

### Phase 1 — Scalability quick wins (DONE, 2026-08-25)
- **Batching** (`translator.format_batch_for_siem`): Splunk HEC `[{"event":…}]`,
  Sentinel/Datadog arrays. `BATCHABLE_SIEMS = {splunk, sentinel, datadog}`;
  elastic/generic ship one alert per POST.
- **Concurrent delivery** (`orchestrator.deliver_concurrently`): one worker per
  (tenant, SIEM) group → per-tenant isolation + per-tenant ordering preserved.
- **Retry + backoff** (0.5s→1s→2s, `--retries 2`) and **dead-letter queue**
  (`dead_letter_queue.jsonl`).
- **Config cache** (`config_store`): stat-based (mtime+size), auto-invalidates on save.
- **Timing/throughput** in the run summary (`elapsed_seconds`, `delivered_per_sec`).
- CLI: `python3 orchestrator.py --source synthetic|real --limit N
  --batch-size 10 --max-workers 8 --retries 2`.
- Tests: **39 passing** (`python3 -m unittest discover -s tests`), stdlib only.
- Live real run: 871 → delivered 85 (Splunk batched 3-in-1, Elastic 1-per-POST),
  failed 0, DLQ 0; one transient failure auto-recovered via retry.

**2026-09-01 — Splunk verified against a real instance, and a real gap found in
the currently-shipping pipeline.** `annie-splunk` (Splunk Enterprise in
Docker on `10.2.10.200`, HEC enabled) was already running on Annie but never
wired up or delivery-tested — `onboarding-app/backend/siem_catalog.py` still
had Splunk's `http` transport marked `UNTESTED`. Created a real HEC token,
ran `orchestrator.run_pipeline` (the full engine) against it for real:
`translator.format_for_siem`'s `Authorization: Splunk <token>` header + the
`{"event": {...}}` envelope delivered successfully — HEC returned
`{"text":"Success","code":0}`, 1/1 delivered. Catalog status flipped to
`VERIFIED`; a `test-annie-splunk` entry (mock token, real one kept local)
added to `tenant_configs.json`, matching the Elastic/Wazuh/Graylog pattern.

**Important — this does not verify `ecs_syslog_webhook.py`, the pipeline
that's actually shipping.** Ran the same real Splunk instance through that
module's `run_simple_pipeline` too, and it failed with a real `401`.
`deliver_to_webhook` always sends `Authorization: Bearer <token>` — that's
correct for a truly generic webhook receiver, but real Splunk HEC rejects
anything that isn't `Authorization: Splunk <token>`. Confirmed by isolating
just the header against the same live instance (Bearer → 401, Splunk → 200).

**Fixed same day, Brian's call.** `ecs_syslog_webhook.py` now carries one
documented exception to its own "no per-SIEM branching" rule:
`_AUTH_SCHEME_BY_SIEM` sends `Authorization: Splunk <token>` when
`siem_type == "splunk"`, `Bearer <token>` for everything else. Re-ran
`run_simple_pipeline` against the same live Splunk instance that 401'd
before the fix — `delivered=1, failed=0`. Regression test added
(`test_splunk_gets_splunk_auth_scheme_not_bearer`). Message format,
batching, and retries are unchanged — this is only about the login header.

**Second Splunk bug found and fixed the same day.** `siem_catalog.py`'s
Splunk `url_example` pointed at `/services/collector` — Splunk HEC's JSON
*event* endpoint. The shipping pipeline sends plain text, and that endpoint
400s on it (`"Invalid data format"`, confirmed live). Fixed to
`/services/collector/raw`, HEC's unstructured-text endpoint, which is what
`ecs_syslog_webhook.py` actually needs.

**Bigger finding, not fixed, needs a decision.** Every other SIEM in
`siem_catalog.py` (Elastic, Wazuh, Graylog, Sentinel, Datadog, Sumo Logic,
CrowdStrike) has its `url_example` pointing at that vendor's *structured*
ingestion endpoint (bulk NDJSON, GELF JSON, etc.) — built for
`orchestrator.py`'s full engine, which is not what's currently shipping.
`ecs_syslog_webhook.py` only ever sends one plain-text syslog line, to any
URL. Splunk happens to also expose a raw-text endpoint, which is the only
reason it works at all today. Confirmed the same rejection pattern
Splunk's JSON endpoint gave (`400`, `"Invalid data format"`) is what any
JSON/NDJSON/GELF-schema endpoint would give a non-JSON body — not
independently re-tested against Elastic/Graylog's real instances, but the
same reasoning applies. Practical effect: **only Splunk and a true generic
webhook receiver can actually receive data from today's shipping
pipeline** — the other 7 catalog entries describe a real, tested, working
format, just not one the currently-running pipeline produces.

### Phase 2 — Async core (NEXT)
- Async HTTP delivery (`httpx.AsyncClient` / `asyncio`) — remove the
  `ThreadPoolExecutor` ceiling; per-tenant asyncio queues for ordering with
  within-tenant concurrency.
- **Continuous API feed**: implement `iter_api_stream(endpoint, api_key)` in
  `ingest.py` (same generator contract) with checkpointing/resume + pagination.
- **Durable queue / backpressure** between ingest and delivery (Redis or
  SQLite-WAL → Kafka/PubSub when volume demands). Wire/replace
  `queue_manager.py` (currently unwired legacy).
- Time-based batch flush (e.g. flush every 5s even if batch not full).
- Elastic **bulk NDJSON** support (it's the only non-batchable target today).

### Phase 3 — Production hardening
- Containerize the Data Plane + autoscale consumers.
- DB-backed config (SQLite → Postgres) + **secrets manager** for webhook tokens
  (currently plaintext in `tenant_configs.json`).
- Observability: Prometheus metrics (delivered/sec, latency percentiles, queue
  depth), structured logs to file, request tracing.
- Multi-replica safe delivery (idempotency keys, at-least-once + dedupe).

## Commands

```bash
cd "ChatGPT/Aman SIEM Pipeline"

# Data Plane — synthetic or real export
python3 orchestrator.py --source synthetic
python3 orchestrator.py --source real --batch-size 10 --max-workers 8 --retries 2

# Control Plane — CLI dashboard (writes tenant_configs.json)
python3 mock_dashboard.py

# Control Plane — Streamlit UI
python3 -m streamlit run dashboard_app.py --server.headless true --server.port 8501

# Tests (stdlib unittest, zero install)
python3 -m unittest discover -s tests
```

## Resume checklist (tomorrow)

1. `python3 -m unittest discover -s tests` — expect 39 OK.
2. `python3 orchestrator.py --source real` — expect 85 delivered, DLQ 0.
3. Open http://localhost:8501 (or relaunch per commands above).
4. Start Phase 2, item 1: async delivery (`httpx`); add `httpx` to deps.
5. When the API endpoint + key are provided, implement `iter_api_stream` in
   `ingest.py` and add the `--source api` flag.

## Notes / decisions

- `gambling` = Medium severity (per Brian, 2026-08-25).
- Real export timestamps are UTC and naive — normalizer treats them as UTC.
- The Downloads CSV is a **sample only**; the production feed will be a
  continuous API stream (key-based). `normalize_to_ocsf` is source-agnostic.
- Translator gaps still open (from the audit, not yet fixed): Datadog body must
  be an array (Phase 1 batching now handles this for batched paths), Sumo Logic
  needs `Basic <base64>` auth, CrowdStrike LogScale needs HEC `{"event":…}`.
