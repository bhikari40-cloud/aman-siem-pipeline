# Handoff — Aman SIEM Pipeline

**Repo:** `github.com/bhikari40-cloud/aman-siem-pipeline`, branch
`customer-onboarding-gate` (this is the default branch — it's what you see
when you open the link).

## What this is

Aman blocks malicious/unwanted DNS queries. A customer's SOC wants to see
the ones that got blocked, inside whatever SIEM they already run. Current
scope, stated plainly: **we push the data to their webhook, in a standard
format. Getting it to show up as a native "alert" in their SIEM's own UI is
the customer's own setup, not ours.**

## In plain terms, before the technical detail

`tenant_configs.json` is the address book — one entry per customer, holding
where to send their alerts and how to get in. Every alert gets checked
against it first; unknown customer, nothing gets sent. It's written under a
file lock because two tools can save to it at once (the signup page, the
internal dashboard), and without that lock one save can silently erase the
other's change.

The signup link is a one-time claim ticket, not a plain ID. It contains a
random token, not the customer's real ID, and works once — the moment they
submit their webhook, it's marked used. A fake, expired, used, or revoked
token all produce the exact same "invalid link" error, on purpose, so a
failed attempt can't be used to confirm a real token or customer exists.

Full technical walkthrough, with diagrams and a worked example: `README.md`.

## What's actually proven

`ecs_syslog_webhook.py`: for each blocked DNS event, builds one message —
the event's fields in Elastic's own standard naming (ECS), wrapped as a
syslog-formatted line — and sends it as a plain HTTP POST to that specific
customer's webhook URL. Tested (69 tests, `python3 -m unittest discover -s
tests`), and verified for real: I generated a real one-time sign-up link,
submitted a webhook through the actual running sign-up page, and confirmed
the event arrived at that webhook correctly formatted.

Since then, also verified against a real Splunk instance (not just the
sign-up-page test above) — two real bugs turned up doing that, both fixed
and covered by tests: the wrong login header (was sending a generic one
Splunk rejects), and the wrong URL path (was pointing at Splunk's JSON
endpoint, which 400s on the plain text this pipeline sends). Datadog had
the same kind of login-header bug, fixed the same way, but not yet
live-verified against a real Datadog account the way Splunk was. Real
vendor research (cited sources, not guessing) found that Elastic, Graylog,
Sumo Logic, and CrowdStrike Falcon LogScale can each receive this same
format too, just at a different address than the "native" one
`siem_catalog.py` lists for them. Wazuh and Microsoft Sentinel are the two
that genuinely can't receive it directly — either needs a customer-built
relay in front of it. Full detail: `PROGRESS.md`'s 2026-09-01 entries.

A draft customer-facing setup guide now exists too:
`docs/Aman-SIEM-Pipeline-Customer-SIEM-Configuration-Guide.docx`, with
real, vendor-verified steps per SIEM. Marked DRAFT — nobody's reviewed it
for customer-readiness yet, and it has no support-contact info in it since
none was given to put there.

## Important — what's prototype vs. real

**`onboarding-app/` (the sign-up page a customer uses to submit their
webhook) is a proof-of-concept, not the real product.** It's a small
standalone web page (`localhost:5173`) built to prove one thing: that a
customer can submit their own webhook, and the pipeline picks it up and
delivers to it correctly. It does that, and it works.

**In the real product, a customer will enter this same information (their
SIEM's webhook address, their auth token) inside the actual IntelliBroń Aman
dashboard** — not in this separate prototype page. Whoever builds that real
flow doesn't need to reinvent anything: the prototype's backend
(`onboarding-app/backend/`) shows exactly what to capture from the customer
and how it's handed to the delivery pipeline (a small file per customer,
`tenant_configs.json`, holding their webhook URL + token). The real Aman
dashboard's backend should write to that same shape — either by reusing this
code directly, or by copying the pattern.

## How it works, in order

1. A customer's webhook + token gets saved somewhere (today: the prototype
   sign-up page; eventually: the real Aman dashboard).
2. A blocked DNS event comes in.
3. It's matched to that specific customer, and to nobody else's webhook.
4. It's turned into one ECS-formatted message and POSTed to their webhook.
5. Nothing is sent for events that weren't actually blocked, and nothing is
   sent if a customer hasn't set anything up yet.

## What's not done / needs a decision

- There's a second, more capable version of this pipeline
  (`orchestrator.py` / `translator.py`) that also builds real native alerts
  for specific SIEMs (e.g. a working Kibana alert rule, a working Wazuh
  alert rule). It's real and tested, but it's not what's shipping right now
  — current instruction is "push data only, alerting is the customer's job."
  It's kept in the repo in case that decision changes later.
- No real customer has gone through this yet — only the sign-up-page test
  described above.
- Deeper technical detail and history: `ARCHITECTURE.md`, `PROGRESS.md`.
