# grpcscope

An internal-network gRPC exposure scanner. It finds gRPC services, enumerates
their RPCs, and identifies administrative or state-changing methods that are
reachable without authorization — **without ever invoking one**.

It exists because of a specific, common failure: several hundred Go services
share a network, many enable gRPC server reflection "to help with debugging",
and management methods are registered on the same port as business methods. A
tester who can reach any one of them can list every method and call the ones
that flush caches or rewrite configuration. This tool answers, for the whole
fleet at once and repeatedly as addresses change:

- which endpoints speak gRPC,
- which expose reflection (the inventory-leak symptom),
- which methods are registered, with their cardinality and input fields,
- which of those are state-changing or administrative,
- and whether each appears callable without credentials, with the evidence
  behind that claim.

## The problem it solves safely

The hard part is not enumeration but **not touching what you enumerate**.
A network scanner that "just calls every method to see what happens" will, on
an internal services fleet, eventually flush a cache, drain a queue, or restart
a node. The tool is built around one invariant:

> **No request body reaches user code unless the mode and the method's risk
> verdict both permit it, and a state-changing or administrative method is
> never called.**

### How existence is proven without running code

Sending deliberately-corrupt protobuf bytes to test "does this method exist"
is unsafe for **client-streaming and bidi** methods: Go's generated
`*_Handler` for a client-streaming RPC calls into user code *before* decoding
the first message, so the handler body runs (and whatever it does before its
first `Recv`) before any decode error is raised. That was measured, not assumed
(see *Verification* below).

Instead the tool uses an **encoding oracle**: a raw HTTP/2 request shaped like a
gRPC stream open, carrying `content-type: application/grpc` and a
`grpc-encoding` value nobody registers, with no body at all. grpc-go's server
checks that header before it selects a decoder, dispatches the method, or runs
any interceptor or handler, and replies:

| Reply | Meaning |
|---|---|
| `Decompressor is not installed for grpc-encoding "..."` | service **and method exist** |
| `unknown method X for service Y` | service exists, method does **not** |
| `unknown service Y` | service does **not** exist |

All three are distinguishable, the marker-encoding recurrence is proof the path
is registered, and **no handler code runs for any cardinality**. This holds
even when an auth interceptor is installed, because the decompressor check
precedes the interceptor chain.

The tool sends this oracle as raw HTTP/2 rather than through grpc-go's client
on purpose: a grpc-go client refuses to send a compression name that it has not
registered in its own process-wide encoding registry, and registering the marker
compressor would make it visible to any gRPC server started in the same process,
silently defeating the safety property. Raw headers have no such coupling.

### Authorization verdicts, honestly labelled

A body is sent only as far as the mode allows:

| Mode | Bodies sent |
|---|---|
| `safe` (default) | none — reflection, health check, encoding oracle only |
| `standard` | empty requests to **read-only-named, non-administrative** methods with a known descriptor |
| `aggressive` | empty requests to any unary method with a known descriptor and no `required` fields (isolated test environments only) |

Each method gets one of four auth verdicts, and the report never dresses an
inference up as a proof:

- `proven-open` — an inert call succeeded without credentials,
- `proven-gated` — an inert call was rejected with an auth code,
- `inferred-open` / `inferred-gated` — the server-wide health check succeeded
  or failed unauthenticated and this method lives beside it; **the method was
  not called**,
- `unknown` — nothing safe could establish it.

The standard health check (`grpc.health.v1.Health/Check`) is inert by protocol
definition and is the one legitimate server-wide signal: if it answers without
credentials, no global unary interceptor is enforcing auth. That is the basis of
the `inferred-*` verdicts, and the report says so explicitly.

### The risk classifier gate

Method and service names, plus input field names when a descriptor is known,
drive the risk verdict (`destructive` / `mutating` / `read-only` / `unknown`),
and every verdict carries its reasons. Sending a body additionally requires
`risk.BodyProbeSafe`, which is stricter than the method verdict: **any method on
an administrative service is barred from body probes regardless of its verb**,
because `AdminService/WatchAdmin` or `AdminService/GetConfig` read benign but
are management operations.

## Enumeration sources, strongest first

1. **Reflection** (v1, then v1alpha) — exact services, descriptors, shapes, and
   input fields. The scanner flags it as a finding, since its exposure is half
   the problem.
2. **Supplied descriptors** — a `.proto` file/dir or a compiled
   `FileDescriptorSet`. A company that builds Go services from `.proto` files
   already has this; it turns guessing into reading.
3. **Wordlists** — used only when reflection is absent. A guessed name enters
   the inventory **only after the encoding oracle confirms it**; invented
   services and methods are dropped, and confirmed ones are labelled `guessed`.

Every discovered method is re-confirmed with the oracle
(`probe.confirm_with_oracle`), so a `.proto` describing a build the server does
not run yields an empty inventory, not a false one.

## Usage

```sh
go build -o grpcscope ./cmd/grpcscope

# fastest look: does a single address expose reflection / admin methods?
grpcscope scan -addr 10.12.3.40:50051 -formats markdown

# a plan file, with descriptors and a safety veto list
grpcscope scan -config config.example.yaml

# a sweep, with wordlist fallback for servers without reflection
grpcscope scan -cidr 10.12.0.0/24 -ports 50051,9090 -mode standard

# compare against the previous run (what appeared, what lost its auth)
grpcscope diff -out results

# prove the safety property end to end against an in-process demo server
grpcscope selftest
```

`config.example.yaml` documents every field. Notable flags:

- `-mode safe|standard|aggressive` — body-probe escalation, default `safe`.
- `-never-call 'regex'` / `-never-touch 'regex'` — veto lists matched against
  `/pkg.Service/Method`. `never_call` bars any request body; `never_touch`
  exempts a path from all probing, even the oracle. `-allowed-call 'regex'`
  re-opens body probes inside a `never_call` region (but never inside
  `never_touch`).
- `-rate` — requests per second across the whole scan (default 200); an
  unbounded sweep of a shared segment is its own incident.
- `-allow-large` — required to exceed `safety.max_targets` (default 5000), so a
  mistyped CIDR cannot become a multi-hour scan.

## What it will not do

- Invoke a method classified `mutating` or `destructive`, in any mode.
- Send a body to any method on an administrative service.
- Report a method as present without wire proof from the oracle.
- Present an inferred authorization verdict as a proven one.
- Claim reflection is absent when the reflection service is present but
  malfunctioning (that is reported as `error`, distinct from `absent`).

## Verification

The claims above are enforced by tests in this repository, not just asserted:

- `internal/wire/oracle_test.go` — the oracle proves existence for every shape
  while the demo server's global handler-entry counter stays at **zero**.
- `internal/scan/engine_test.go` — a `safe`-mode scan of a vulnerable server
  flags the admin methods as exposed while **no handler runs**; an auth
  interceptor flips every verdict to gated.
- `internal/scan/standard_test.go` — in `standard` mode, only read-only,
  non-administrative methods receive a body; every `AdminService` method stays
  uncalled and `inferred`.
- `internal/scan/guess_test.go`, `descriptor_test.go` — guessing and
  descriptor paths both reject invented entries and run no handler.
- `grpcscope selftest` — the same end-to-end property as a runnable command.

The shape-dependent safety finding (client-streaming/bidi handlers entering
user code before decode) and the oracle's pre-handler placement were measured
against grpc-go 1.83 across unary, server-streaming, client-streaming and bidi
methods, with and without unary and stream interceptors, and cross-process to
rule out shared-encoder artifacts.

## Layout

```
cmd/grpcscope        CLI, config merging, output, selftest, diff
internal/wire        the encoding oracle (the safety-critical piece)
internal/fingerprint protocol classification: grpc / http2 / http1 / tls / closed
internal/reflection  v1 + v1alpha enumeration and descriptor linking
internal/descriptors .proto and descriptor-set compilation
internal/scan        per-endpoint orchestration, auth verdicts, findings
internal/risk        name- and field-based risk classification
internal/report      markdown and SARIF rendering
internal/store       on-disk scan history and diffing
internal/testserver  in-process vulnerable demo server for tests
```

## Limitations

- The risk classifier is heuristic. A `read-only` verdict on a harmless-sounding
  name is not a guarantee; `mutating`/`destructive` over-flagging is
  intentional and preferred.
- Auth verdicts for sensitive methods are inferences from server-wide evidence,
  never per-method proof, because proving a sensitive method open means calling
  it. The report distinguishes the two.
- A server with an unknown-service handler (`grpc.UnknownServiceHandler`) makes
  enumeration by absence unreliable; the scanner detects that (a bogus path is
  accepted) and reports it.
- Perfect-shaped payloads for arbitrary schemas are out of scope; the tool
  proves existence and reads descriptors rather than fuzzing arguments.
