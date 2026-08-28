# Aman SIEM Pipeline — Architecture & Status

What works, why it works, and what's deliberately out of scope. Written after
the session that took this from "delivers to one SIEM" to "delivers to
Elastic, Graylog, and Wazuh, each in its own native format, with two of the
three producing genuine native alerts." Companion to `PROGRESS.md` (which
tracks phase/todo status) — this doc is the reference for *why things are
built the way they are*, so a future change doesn't accidentally undo a
lesson that cost real debugging time to learn.

---

## 1. What this is

Aman's DNS security product generates raw logs. A customer's SOC wants those
logs — specifically the *actionable* ones — inside whatever SIEM they already
run, in that SIEM's own language, without their admin having to write custom
parsers. This pipeline is the thing in the middle that makes that true.

Three tiers:

```
ClickHouse (source)  →  Translation Engine (this codebase)  →  Customer's SIEM
 real DNS log data       normalize → filter → format → deliver    Elastic / Graylog / Wazuh
```

The live dashboard's source used to be Hinata's synthetic demo stream
(tailed live over SSH). It now pulls real production DNS log rows from the
internal ClickHouse data API (`clickhouse-api.malcolm.intellibron`,
`intellibron_aman_silver.dns_request_parsed`) instead — Hinata is no longer
part of this pipeline's live path. See 3.1 and 6 for what changed and what's
explicitly still out of scope.

The translation engine is the actual product here — it's the only tier we
control end to end, and it's where every "why does this work for every SIEM"
answer lives. Sections 3–4 below go deep on it deliberately.

---

## 2. The big picture

```
raw doc ──► ingest.normalize_to_ocsf ──► canonical OCSF alert
                                              │
                                              ▼
                          orchestrator.should_deliver_event
                          (tenant isolation, then: was this blocked?)
                                              │
                                   dropped ◄──┴──► kept
                                (unknown tenant,        │
                                 benign/allowed)         ▼
                                          translator.format_for_siem /
                                          format_for_syslem  (per-target)
                                              │
                                              ▼
                          orchestrator.deliver_batch / deliver_one
                          (HTTP bulk / HTTP single / raw UDP — by webhook_url scheme)
                                              │
                                              ▼
                                     Elastic · Graylog · Wazuh
```

Two live components exercise this path today:

- **`orchestrator.py` / `translator.py` / `ingest.py` / `config_store.py`** —
  the actual product code. Tested (55 unit tests, stdlib `unittest` only, zero
  install), used by both the CLI (`orchestrator.py --source real`) and the
  live dashboard.
- **`live_dashboard.py`** — a continuous test harness that pulls real rows
  from the ClickHouse data API (`ingest.iter_api_stream`) and drives the
  *same* translator/orchestrator functions in real time, with a
  browser-viewable diagram (`http://localhost:8901`) showing the same
  event's shape changing at each destination. Not a simulation of the
  pipeline — it calls the pipeline's own code. Needs
  `~/.config/clickhouse-api.env` sourced (`CLICKHOUSE_API_URL`,
  `CLICKHOUSE_API_KEY`) before launching, or the stream thread logs a
  message and never starts. The stream loop restarts itself with a 10s
  backoff on any failure (the backend has real, reproducible reliability
  issues — see 6) rather than letting one bad response kill the background
  thread silently.

---

## 3. The translation engine, in depth

### 3.1 `ingest.py` — normalize_to_ocsf

Turns whatever shape a raw log arrives in (ECS-ish nested dicts from the
synthetic generator, or a real OpenSearch export row) into one canonical OCSF
DNS Activity (class 4003) alert. Everything downstream — filtering,
formatting, delivery — only ever looks at this canonical shape. This is the
seam that makes a new raw source (a real continuous API feed, eventually)
a non-event for the rest of the pipeline: implement one more `iter_*`
generator yielding raw docs, nothing else changes.

**Dialect gap now moot for the live path.** Hinata's own OCSF mapper (a
separate codebase, richer in some fields but missing `tenant` and using
epoch-millis timestamps) used to require the pipeline to tolerate its shape
via `live_dashboard.py`'s tenant-injection step. Since the live dashboard now
sources from ClickHouse — raw ECS-shaped rows (`_clickhouse_row_to_raw_doc`)
that go through the *same* `normalize_to_ocsf` path as the CLI's OpenSearch
CSV export — that tolerance code is no longer exercised anywhere live. Left
in place (`live_dashboard.process_event` still injects `tenant.uid` per
backend, same as before) since nothing forces its removal, but the
Hinata-dialect mismatch itself is dead history, not an open item.

### 3.2 `orchestrator.py` — the pipeline stages

Per event, in order:

1. **`should_deliver_event`** — tenant isolation (`alert.tenant.uid` must have
   a config) then the blocked-alert filter (`disposition == "Blocked"`).
   Everything that survives this is, by definition, something a SOC would
   want to see. This is the single most important design decision in the
   whole system — see 3.4.
2. **`prepare_delivery_attempt`** — picks HTTP or syslog transport from the
   tenant's `webhook_url` scheme, then hands off to `translator.py` for the
   actual per-target formatting.
3. **`group_into_batches` / `build_batch`** — arrays-envelope SIEMs
   (Splunk/Sentinel/Datadog) get real batching; Elastic/Wazuh's NDJSON bulk
   body batches too, but via concatenated bulk records, not a JSON array;
   syslog never batches (RFC 5426: one datagram is one record, by
   convention) regardless of what its `siem_type` would otherwise allow.
4. **`deliver_concurrently` → `deliver_batch`** — one worker per
   (tenant, SIEM) group, so a slow/failing tenant can't block another
   tenant's delivery, retry with exponential backoff, dead-letter queue for
   exhausted retries.

### 3.3 `translator.py` — the actual "translation"

This is the module that answers "how does the same event become three
different shapes." Two entry points, one per transport:

**`format_for_siem` / `format_batch_for_siem`** (HTTP transport) — picks the
envelope per product:

| Target | Envelope | Auth |
|---|---|---|
| Splunk | `{"event": {...}}` (HEC) | `Splunk <token>` |
| Sentinel | `[{...}]` | `Bearer <token>` |
| Datadog | `[{...}]` | `DD-API-KEY` header |
| Elastic / Wazuh | NDJSON bulk (`{"index":{}}\n{...}\n`) | `ApiKey <token>` (Elastic) / `Basic <base64>` (Wazuh) |
| Graylog | GELF JSON | none configured on this input |

**`format_for_syslog`** (UDP transport) — a *separate* dispatch, because
syslog needs a compact body and "compact" means something different per
target. `_SYSLOG_BODY_BUILDERS` keys off `siem_type`:

| Target | Body format | Why this one |
|---|---|---|
| Wazuh | Compact JSON | Matches Wazuh's built-in JSON decoder (`offset="after_prematch"` skips the syslog header, no custom decoder needed just to *receive* it) |
| Graylog | Compact `key=value` | Matches the generic key/value extractor Graylog ships with out of the box — same reasoning, no custom parsing required just to receive it |

The body itself (`_compact_syslog_fields`) is deliberately *not* the full
OCSF alert — only `domain`, `src_ip`, `severity`, `tenant`, `rule`. UDP has a
real truncation risk (one dropped/fragmented datagram silently corrupts the
whole message, worse over lower-MTU paths), and RFC 5424's own header
already carries a timestamp, so there's no reason to duplicate it in the
body. Full fidelity still goes out over the non-UDP channels — this is a
"compact by design where it matters" choice, not a hasty truncation.

**The transport/format split is deliberate.** `siem_type` identifies the
*product* (which format conventions apply); the `webhook_url` scheme decides
the *transport* (HTTP vs. raw UDP socket). The same `siem_type` (e.g.
`"wazuh"`) can be reached over either transport with a different tenant
config — this is exactly how Wazuh ended up wired both ways (bulk API into
its indexer directly, and syslog into its manager for real decoder/rule
processing — see 4.2).

### 3.4 The one decision that answers the scoping question

Your boss's rule: push data to the SIEM is our job; getting it to register
as a *native alert* is the SIEM's own setting, unless we can push that too.

`should_deliver_event` already resolves most of this before it's even a
question: the translation engine decides what counts as alert-worthy
*before anything is sent*. A customer's SIEM only ever receives documents
that are already the alert — no customer-side filtering, no correlation
rule needed just to see something meaningful. That's why Elastic's Discover
and Graylog's Search both showed real, actionable data immediately, with
zero configuration on the receiving end, from day one of testing.

The remaining question — does it *also* show up in the SIEM's own native
"Alerts" UI (Kibana Security Alerts, Graylog Events, Wazuh's own alert
level) — is genuinely a second, separate thing, because each platform's
native alerting is a rule/decoder system that operates on top of received
data, not a property of the data itself. Section 4 covers where that landed
per target.

### 3.5 Bugs found and fixed here (worth knowing before you touch this code)

These weren't hypothetical edge cases — each one actually produced wrong or
silently-dropped data during real testing this session.

- **A lone Elastic/Wazuh alert used the wrong envelope for `_bulk`.**
  `format_for_siem`'s single-alert path returns a plain JSON object, correct
  for a `_doc` endpoint but not for `_bulk`, which always needs the NDJSON
  body — even for one record. `orchestrator.build_batch` now forces the bulk
  path whenever `siem_type in NDJSON_BULK_SIEMS`, regardless of count.
  Caught by `test_lone_elastic_or_wazuh_attempt_still_batches_as_ndjson`.

- **Elasticsearch's Bulk API can return HTTP 200 while silently rejecting a
  document.** A per-item failure (we hit this for real: a `time` field
  type conflict — see next point) only shows up in the response body's
  `errors`/`items` fields, never the status code. Code that only checked
  `response.status_code` treated total failures as full successes.
  `orchestrator._first_bulk_item_error` / the equivalent check in
  `live_dashboard.deliver_one` now parse the bulk response body explicitly.
  Caught by `test_run_pipeline_catches_bulk_item_errors_despite_http_200`.

- **`time` field type conflict, `long` vs. string.** Elasticsearch's dynamic
  mapping locks a field to whichever type it sees first. Hinata's numeric
  epoch-millis timestamps mapped `time` as `long` first; documents from our
  own `ingest.normalize_to_ocsf` (which emits `time` as an ISO string) then
  hard-failed with `document_parsing_exception` against that same index —
  silently, per the point above. Fixed by normalizing `time` to a consistent
  ISO string *and* adding a matching ECS `@timestamp` inside
  `translator._to_bulk_ndjson`, so Elasticsearch's dynamic mapping types it
  as a real `date` field. This is also what unblocked Kibana's detection
  rule (see 4.1) — it can't run a time-range query against a field with no
  usable date type.

- **Wazuh's syslog remote config needs both `<remote>` blocks in the *same*
  `<ossec_config>` wrapper.** A second, separate `<ossec_config>` block
  (which is valid XML and does merge for most Wazuz config sections) gets
  silently ignored by `wazuh-remoted` specifically — it only picks up the
  first `<remote>` block it finds. Fixed by adding the syslog block as a
  sibling of the existing TCP block, in the same wrapper, in both the live
  container config *and* the host-side source file it gets re-copied from
  on every container start (editing only the live file doesn't survive a
  restart).

- **A "GELF-HTTP silently drops alerts" finding was retracted.** Extensive
  investigation (DEBUG/TRACE logging on Graylog's `DecodingProcessor`,
  journal inspection, reading the actual open-source `GelfDecoder.java`)
  found no real drop — the messages were landing correctly the whole time.
  The false alarm came from my own verification method: an OpenSearch
  `match_phrase` query against a truncated search term that didn't match
  the full indexed token. Lesson: when a "the data isn't there" finding
  and a "the pipeline reports success" finding disagree, distrust the
  *verification* method before concluding the pipeline is broken — check
  with a `match_all`/direct listing, not a hand-constructed query, before
  trusting a negative result.

- **Kibana rejects the `elastic` superuser for its own connection.** Once
  `xpack.security` is enabled, Kibana 8.x requires a real service-account
  token (`POST /_security/service/elastic/kibana/credential/token/...`),
  not username/password with the superuser. A separate, properly-scoped
  API key (write-only on `aman-live-test`, not superuser) was generated for
  the pipeline's own delivery — least-privilege by default, not just for
  Wazuh's still-open TODO (see 6).

---

## 4. Per-SIEM integration status

### 4.1 Elastic (and native OpenSearch, same wire protocol)

- **Transport/format:** HTTP, Bulk NDJSON, full-fidelity OCSF document.
- **Auth:** `xpack.security` enabled; pipeline uses a scoped API key
  (write-only on `aman-live-test`), not the superuser.
- **Native alerting:** **working.** A Kibana Security detection rule
  (`disposition: "Blocked"` on `aman-live-test`, 1-minute interval) runs
  successfully and produces real entries in
  `.internal.alerts-security.alerts-default`. Getting here required, in
  order: setting `xpack.encryptedSavedObjects.encryptionKey` (Kibana won't
  start its Alerting subsystem without it), enabling `xpack.security` itself
  (was off for ease of early testing), fixing the Kibana-superuser-forbidden
  issue above, and the `@timestamp`/bulk-error fixes in 3.5. Every one of
  those was a real, separate blocker — this wasn't one fix, it was five.

### 4.2 Wazuh

Two independent paths, deliberately different in what they achieve:

- **Bulk API → Wazuh's indexer directly** (`test-annie-wazuh`, port 9202,
  HTTPS, self-signed cert). Writes the full OCSF document straight into
  Wazuh's OpenSearch-compatible indexer. This bypasses Wazuh's own
  manager/rule engine entirely — the data is there and browsable, but it
  isn't a "real" Wazuh alert in Wazuh's own sense. **Known gap:** this path
  currently authenticates as `admin` — full superuser access to Wazuh's
  entire data store, not scoped. Flagged, not yet fixed (see 6).
- **Syslog → Wazuh's manager** (`test-annie-wazuh-syslog`, port 514/UDP).
  Goes through Wazuh's actual intended ingest path. A custom decoder
  (`aman-pipeline`, in `local_decoder.xml`) extracts `domain`/`src_ip`/
  `severity`/`tenant`/`rule` from the compact JSON syslog body, and rules
  100050–100054 (in `local_rules.xml`) escalate by our own `severity` field
  (Low→5, Medium→8, High→12, Critical→15). **Native alerting: working** —
  verified via `wazuh-logtest` and a live delivery landing in
  `/var/ossec/logs/alerts/alerts.json` with the correct rule and level.

### 4.3 Graylog

- **Transport/format:** syslog UDP, compact `key=value` body. (A GELF-HTTP
  path also exists and works — see the retracted-bug note in 3.5 — but
  syslog is what's actually wired into the live tenant config, chosen for
  UDP compactness, not because GELF-HTTP was broken.)
- **Native alerting: blocked by a Graylog defect, not a config issue.** An
  Event Definition's scheduler trigger fires exactly on schedule, but the
  job record it's supposed to execute never persists to MongoDB — zero
  errors logged anywhere, survives a full container restart, and a control
  Event Definition with a query completely unrelated to our data (`query:
  "*"`, matching anything Graylog has ever received) hit the exact same
  failure. That control test is what rules out our data/pipeline as the
  cause — a query with zero connection to our data shouldn't fail the same
  way ours does unless the failure is in Graylog itself.

---

## 5. Scope boundary (per the boss's rule)

| | Pushing data | Native alert |
|---|---|---|
| **Elastic** | Our job — done | Our job (rule pushed via API, zero customer clicks) — **done** |
| **Wazuh** | Our job — done | Our job (decoder+rule pushed via config, zero customer clicks) — **done** |
| **Graylog** | Our job — done | Attempted, blocked by a vendor defect — **not our job to fix** |

The distinguishing test throughout: if closing the gap requires an API call
or a config file *we* can push, it's our job. If it requires flipping a
setting on a security subsystem the customer already chose to run a certain
way (Elastic's `xpack.security`, in a real deployment, already on) — or if
it's blocked by a bug in the vendor's own software with no user-facing
workaround — it isn't.

---

## 6. Known limitations / explicitly not done

- **Wazuh's bulk-API path uses `admin` (superuser), not a scoped credential.**
  Should be a write-only role/user, matching what was done for Elastic.
  Only a gap because it was a test-convenience shortcut, not a design
  choice — should not ship as-is.
- **No dashboard UI field for `verify_ssl`.** `config_store.py` and
  `orchestrator.py` support it (needed for Wazuh's self-signed cert); the
  Control Plane's config form doesn't expose it yet.
- **Secrets are plaintext** in `tenant_configs.json` — flagged in
  `PROGRESS.md`'s Phase 3 already, unchanged.
- **ClickHouse data API is not continuous or fresh.** `iter_api_stream`
  queries `max(dt)` and replays one day's slice — real data as of that day
  (currently ~18 days old), not a live tail. Making this real-time requires
  backend-side changes that are explicitly not this pipeline's call.
- **ClickHouse data API has real, reproducible performance/reliability
  issues even at small row counts.** `LIMIT 5` sometimes succeeded in ~4.5s;
  `LIMIT 10`/`LIMIT 20` both hit 30s timeouts in repeated testing, and a
  sustained 502 Bad Gateway has also been observed directly — not a clean
  threshold, genuine backend-side inconsistency. `_clickhouse_query` retries
  transient failures (2 retries, 1s backoff); `live_dashboard.stream_loop`
  restarts the whole stream after a 10s backoff if that retry budget is
  exhausted, so the dashboard survives a backend outage instead of dying
  silently — but the underlying instability is unfixed, by design: per
  explicit instruction, this is the backend team's problem, not ours. Query
  is also deliberately unordered (`ORDER BY` made timeouts worse), so a
  restarted stream can redeliver rows already seen — acceptable for proving
  connectivity, not a claim of exactly-once delivery.
- **Fixed 2026-08-27: unordered `LIMIT 10` could deliver nothing, forever,
  while looking alive.** Because the query is unordered against an immutable
  partition, it's deterministic — every stream restart re-fetched the exact
  same 10 rows (verified directly: two identical calls returned identical
  rows in identical order). On the day being read, none of those 10 rows
  happened to be blocked, so `should_deliver_event` dropped all 1137 replayed
  events and `generated`/`dropped_unblocked` climbed together while
  `last_event` stayed `null` forever — the dashboard looked dead, but the
  stream thread, retries, and backoff were all working correctly; the bug was
  upstream, in what got sampled. Fixed by adding `AND destination_blocked =
  true` to `iter_api_stream`'s SQL (`ingest.py`): the demo only ever cared
  about blocked events anyway (everything else gets dropped downstream), so
  filtering server-side both fixes the stuck-on-benign-slice failure mode and
  stops spending the small `LIMIT` budget on rows that were never going
  anywhere.
- **Fixed 2026-08-27: `aman-live-test`'s stale `time: long` mapping on the
  Wazuh indexer.** Delivering a live event to `test-annie-wazuh` post-fix hit
  the exact `time`-field-type conflict described in 3.5 (`long` vs. ISO
  string) — but against *this* index specifically: it carried a `long`
  mapping locked in by a document written before the `_to_bulk_ndjson` fix
  existed (confirmed directly via `GET aman-live-test/_mapping/field/time`
  before touching anything). Fixed by deleting and recreating the index
  (2340 pre-existing docs, all POC/test data, none of it load-bearing) with
  an **explicit** mapping — `time` and `@timestamp` both set to `type: date`
  at creation time, rather than left to dynamic inference. This is a step
  more robust than the existing code-side fix: Elasticsearch's `date` type
  natively parses both ISO-8601 strings (this pipeline's output) *and*
  epoch-millis integers (hinata's old OCSF mapper's shape) via its default
  format list, so this specific field can no longer get locked to the wrong
  type by whichever producer happens to write first — closes the bug class,
  not just this instance of it. Verified live: post-recreate, `delivered`
  climbed steadily (4→20+) with zero new failures, doc count in the index
  matched `delivered` exactly; the ~70 failures in that run's counter are
  all from before the recreate and are cumulative, not ongoing (`orchestrator`
  status counters aren't reset by an external mapping fix, only by a fresh
  process restart).
  Consider applying the same explicit-mapping treatment to the *Elastic*
  `aman-live-test` index (a separate cluster/index from Wazuh's, per 4.1) —
  it currently relies on the same dynamic-inference-plus-hope pattern this
  bug just proved isn't durable, it just hasn't been hit yet because nothing
  has written a numeric `time` to it first. Not done here — out of scope for
  what was asked, flagging only.
- **No pagination.** `iter_api_stream` pulls a single bounded page
  (`limit=10` at the live dashboard's call site) per stream restart, not a
  full walk of a day's data. Matches the proof-of-connectivity scope this
  was built for — a real replay/backfill tool would need real pagination.
- **Async delivery / durable queue** — still a Phase 2 item from
  `PROGRESS.md`, not touched this session (this session's work was entirely
  about *which SIEMs* and *how faithfully*, and separately, proving
  ClickHouse connectivity — not throughput).

---

## 7. Verifying this yourself

```bash
cd "Aman SIEM Pipeline"
python3 -m unittest discover -s tests                  # 55 tests, stdlib only, no install
set -a && source ~/.config/clickhouse-api.env && set +a
python3 live_dashboard.py                              # live diagram: http://localhost:8901
```

The live dashboard's payload cards (below the diagram) show the same event's
actual wire body at each destination — the fastest way to see "why it works"
rather than read about it.
