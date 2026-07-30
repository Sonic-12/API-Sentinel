# Discovery Pipeline

The Discovery Pipeline is the third stage of API-Sentinel, running after the Rust userspace loader and the Python Parser. It reads the parsed HTTP request events printed by `parser.integration`, builds a live inventory of the API endpoints actually being used, and compares that inventory against the application's own documented API specification to identify undocumented or missing endpoints.

The pipeline is divided into multiple modules, where each module performs a specific task.

---

## pipeline

`pipeline.py` serves as the entry point of the discovery stage.

It continuously reads the JSON output printed by the parser from standard input. Since the parser prints readable, multi-line JSON rather than one compact line per event, the pipeline uses a streaming decoder that extracts each complete object as soon as enough text has arrived. Any non-JSON text in between, such as log lines or plain-text error messages, is simply ignored rather than treated as an error.

This module is responsible only for reading input and coordinating the remaining discovery modules.

---

## normalizer

`normalizer.py` is responsible for recognising when two different requests actually belong to the same endpoint.

A request to `/users/42` and a request to `/users/7` are the same endpoint with a different ID, so this module replaces the ID portion of a path with a placeholder before anything else processes it. It also extracts the literal ID value from a path when needed, and estimates the structure of a JSON request body.

---

## inventory

`inventory.py` maintains the live record of every endpoint observed in traffic.

Each unique endpoint is stored along with how many times it has been hit, a few example paths, the query parameters seen, and the shape of any request body. Every incoming request updates this record, so the inventory always reflects what has actually happened so far.

---

## openapi_generator

`openapi_generator.py` converts the live inventory into a standard OpenAPI document.

This turns the internal record of observed traffic into a format that any other tool, such as a dashboard, can read without needing to understand how the discovery pipeline itself works internally.

---

## comparator

`comparator.py` performs the actual security comparison.

It checks the live inventory against the application's official API specification and identifies endpoints that are being used but were never documented, as well as endpoints that are documented but have never actually been used. Known framework routes, such as the interactive docs page, are excluded so they do not get mistaken for undocumented endpoints.

---

## access_log

`access_log.py` keeps an ordered record of individual requests rather than an aggregated summary.

For every request, it stores who made it, which specific object was accessed, and when. It also carries forward the risk score and alerts already calculated by the parser. This ordered, per-request detail is what makes it possible to later detect a single caller accessing many different objects in a short span of time.

---

## report_writer

`report_writer.py` is responsible for saving all of the above to disk.

Since traffic can arrive far faster than anything needs to read the report, the file is rewritten only periodically rather than on every single request. Each write is done safely, by first writing to a temporary file and then replacing the old report with it, so anything reading the report at the same time never sees an incomplete file.

---

## init

`__init__.py` exposes the parts of the pipeline meant to be used by other code, so they can be imported directly from the package without needing to know which individual file they live in.

---

## Overall Operation

When the parser prints a parsed request, the pipeline reads it, normalises its path, and records it in the live inventory as well as the per-request access log. From this live state, it generates an OpenAPI document of observed traffic and compares it against the application's real specification to flag undocumented or unused endpoints.