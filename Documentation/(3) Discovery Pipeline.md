# Discovery Pipeline

Builds and maintains the live API inventory — the third stage of the pipeline

- Reads the structured JSON the parser prints to stdout — the same events already validated for risk/alerts, not a separate capture path.
- Builds a live inventory of endpoints actually being hit.
- Compares that inventory against the application's documented API spec to surface undocumented ("shadow") or unused endpoints.

Split into single-responsibility modules, listed below in order.

---

## pipeline.py

- Entry point of the discovery stage.
- Reads the parser's stdout via a streaming decoder, since the parser prints readable multi-line JSON rather than one compact line per event.
- Skips any non-JSON text in between (log lines, plain-text errors) rather than treating it as a failure.
- Coordinates the rest of the modules; contains no detection logic itself.

---

## normalizer.py

- Collapses path IDs into templates so `/users/42` and `/users/7` are recognized as the same endpoint (`/users/{id}`).
- Also extracts the literal ID value from a path when needed, and estimates the shape of a JSON request body.

---

## inventory.py

- Maintains the live record of every endpoint template observed in traffic.
- Tracks hit count, a few example paths, observed query parameters, and request body shape per endpoint.
- Updated on every incoming request, so it always reflects actual traffic to date.

---

## openapi_generator.py

- Converts the live inventory into a standard OpenAPI document describing *observed* traffic.
- Lets other tools (the dashboard, in this case) consume a standard format without needing to understand the discovery pipeline's internals.

---

## comparator.py

- Diffs the observed OpenAPI document against the application's actual documented spec.
- Flags **shadow endpoints** (used but never documented) and **unseen documented endpoints** (documented but never actually hit).
- Excludes known framework routes (e.g. the interactive docs page) so they aren't mistaken for shadow endpoints.

---

## access_log.py

- Keeps an ordered, per-request log rather than an aggregated summary.
- Records who made the request, which object was accessed, and when.
- Carries forward the `risk_score` and `alerts` already computed by the parser — no re-analysis happens here.
- This per-request detail is what makes it possible to later see a single identity touching many different objects in a short span.

---

## report_writer.py

- Persists the inventory, diff, and access log to `discovery_report.json`.
- Writes periodically rather than on every request, since traffic can arrive far faster than anything needs to read the report.
- Writes to a temp file first, then renames it into place, so any concurrent reader (the Dashboard API) never sees a half-written file.

---

## \_\_init\_\_.py

- Exposes the pipeline's public modules for import elsewhere without callers needing to know the internal file layout.

---

## Overall Operation

1. The parser prints a validated, structured request to stdout.
2. `pipeline.py` reads it and hands it to `normalizer.py`, which resolves the endpoint template.
3. `inventory.py` and `access_log.py` are updated with the new request.
4. `openapi_generator.py` regenerates the observed-traffic spec; `comparator.py` diffs it against the real spec.
5. `report_writer.py` periodically, atomically writes all of the above to `discovery_report.json`.
6. The Dashboard API (`backend/dashboard_api`) reads that file directly — it never talks to this pipeline, the parser, or the eBPF layer at runtime, keeping the read path fully decoupled from detection.