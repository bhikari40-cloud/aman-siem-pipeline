# Aman SIEM Pipeline

Delivers IntelliBroń Aman's blocked-DNS security events to a customer's own
SIEM, over a webhook they provide, in ECS field names framed as a syslog
message. That's the whole current scope — nothing more.

**Start here:** [`HANDOFF.md`](./HANDOFF.md) — what's proven, how it works,
what's a prototype vs. real, what's left.

## Quick orientation

- `ecs_syslog_webhook.py` — the pipeline. Normalizes an event, checks it was
  actually blocked, sends it to whichever customer it belongs to's webhook.
- `onboarding-app/` — a **prototype** letting a customer submit their own
  webhook URL/token through a one-time link. This proves the pipeline can be
  driven by customer-submitted config. **It is not the real product surface**
  — see `HANDOFF.md` for what that means for production.
- `orchestrator.py` / `translator.py` — a separate, more capable engine that
  also builds native SIEM alerts (a Kibana rule, a Wazuh decoder, etc.) for
  specific platforms. Built and tested, but **not what's currently shipping**
  — see `HANDOFF.md`.

```bash
python3 -m unittest discover -s tests   # run everything
```
