# Python Parser

The Python Parser is responsible for processing the HTTP request events captured by the eBPF program. After the Rust userspace loader receives an event from the kernel and converts it into a JSON object, the parser reads that event, reconstructs the original HTTP request, performs basic security validation, and records any suspicious activity.

The parser is divided into multiple modules, where each module performs a specific task.

---

## integration.py

`integration.py` serves as the entry point of the parser.

It continuously waits for JSON events produced by the Rust userspace loader. Whenever a new event arrives, it reads the JSON data, extracts the hexadecimal HTTP payload, and forwards it to the decoder. If the received event does not represent an HTTP request or contains invalid data, it is ignored.

This module is responsible only for receiving data and coordinating the remaining parser modules.

---

## decoder.py

`decoder.py` is responsible for converting the hexadecimal payload into readable HTTP text.

The eBPF program captures packet data as raw bytes, which are later represented as hexadecimal strings by the Rust userspace application. Since these hexadecimal values cannot be parsed directly as HTTP requests, they must first be decoded into plain UTF-8 text.

The decoded output contains the complete HTTP request, including the request line, headers, and body, which is then passed to the request parser.

---

## request_parser.py

`request_parser.py` processes the decoded HTTP request and extracts meaningful information from it.

It begins by separating the request line from the remaining HTTP message. From the request line, it extracts the HTTP method, requested endpoint, and HTTP version.

The parser then processes all HTTP headers and stores them in a structured format. If query parameters are present in the URL, they are extracted separately. When a request body exists, it is also processed and converted into an appropriate format for later analysis.

After extracting all available information, the module creates a structured request object containing every important component of the HTTP request.

---

## models.py

`models.py` defines the data structures used throughout the parser.

Instead of passing multiple variables between different modules, all parsed information is stored inside a single request object. This object contains the extracted request method, endpoint, headers, query parameters, request body, security alerts, and calculated risk score.

Using a common model ensures that every module works with the same structured representation of the request.

---

## validators.py

`validators.py` performs the security analysis of the parsed request.

Once a request has been successfully reconstructed, this module examines its contents to identify suspicious behaviour. It validates the HTTP method, checks whether protected endpoints are accessed without authorization, identifies requests targeting sensitive endpoints, detects sequential object access that may indicate enumeration attempts, and performs an initial analysis for potential Broken Object Level Authorization (BOLA).

Whenever one of these checks identifies suspicious behaviour, an alert is generated and the corresponding risk score is updated within the request object.

---

## loger.py

`loger.py` is responsible for recording suspicious requests after validation has been completed.

When a request generates one or more security alerts, the logger converts the analysed request into JSON format and stores it in a log file. The stored information includes the parsed request details, generated alerts, and calculated risk score.

These logs provide a persistent record of suspicious API activity that can later be used for analysis, debugging, or incident investigation.

---

## Overall Operation

When an HTTP request is captured by the eBPF program, it is forwarded to the Rust userspace loader, which converts the captured packet into a JSON event. The parser receives this event through `integration.py`, decodes the hexadecimal payload using `decoder.py`, reconstructs the HTTP request using `request_parser.py`, stores the extracted information inside the request model defined in `models.py`, performs security validation through `validators.py`, and finally records any suspicious requests using `loger.py`.

Each module has a single responsibility, making the parser easier to understand, maintain, and extend while keeping the processing workflow clear and modular.