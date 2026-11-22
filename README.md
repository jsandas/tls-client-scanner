# tls-client-scanner

An HTTPS service that reports the TLS capabilities advertised by the client that
connects to it. The same observation is available as an HTML browser report or a
versioned JSON document.

## Run

Go 1.27 or newer is required.

```sh
make build
./tls-client-scanner \
  -address 127.0.0.1:8443 \
  -cert /path/to/server.crt \
  -key /path/to/server.key
```

Then open `https://127.0.0.1:8443/`.

## Endpoints

- `/` renders HTML. It returns JSON when the request sends
  `Accept: application/json` or uses `?format=json`.
- `/api/v1/report` always returns the JSON report.
- `/healthz` returns the service health status.

Example:

```sh
curl --cacert /path/to/ca.crt https://localhost:8443/api/v1/report
```

## Current scope

The scanner uses `tls.ClientHelloInfo` from `crypto/tls` to observe advertised:

- TLS protocol versions
- cipher suites
- supported groups
- signature schemes
- ALPN protocols
- server name

When a handshake completes, the report also includes the negotiated TLS protocol
version, cipher suite, key exchange mechanism, and inferred
`signature_key_type` from the server certificate in the connection state.

GREASE values and unknown registry identifiers remain visible. Findings describe
client advertisements; they do not prove that every advertised option works.

Raw extension bytes, including TLS 1.3 `key_share`, are not captured yet. A
future raw ClientHello parser can feed the same analyzer and report model without
changing the HTTP contract.

## Development

```sh
make test
make build
```

`make test` runs formatting, module-tidiness, `golangci-lint`, and race-enabled
tests.
