# wasm-app-enclave-verifier

A single-purpose [WebAssembly Component](https://component-model.bytecodealliance.org/)
that runs **inside** a [Privasys Enclave OS](https://github.com/Privasys/enclave-os-mini)
instance and verifies a *remote* Privasys enclave by performing an
**RA-TLS handshake** against it.

The whole verification pipeline — TLS chain validation, attestation-quote
parsing, measurement check, ReportData binding, OID extension check, and
optional cryptographic re-verification through one or more attestation
servers — runs **inside the local enclave's egress client**.  The guest
WASM only assembles the policy and inspects the result.

| Property | Value |
|---|---|
| World | `privasys:enclave-verifier/enclave-verifier` |
| Export | `verify(request: verify-request) -> verify-result` |
| Auth tag | `/// @auth public` (no caller authentication required) |
| Imports | `wasi:io@0.2.0`, `wasi:clocks@0.2.0`, `privasys:enclave-os/https@0.1.0` |
| Target | `wasm32-wasip1` (Component Model) |
| License | [AGPL-3.0](LICENSE) |

---

## How it works

```
                      ┌──────────────────────────────┐
                      │  Local Privasys enclave      │
                      │  (enclave-os-mini)           │
   client ──RA-TLS──► │                              │
   verify(request)    │  ┌────────────────────────┐  │
                      │  │ wasm-app-enclave-      │  │
                      │  │ verifier (this app)    │  │
                      │  │                        │  │
                      │  │  1. Build RaTlsPolicy  │  │
                      │  │  2. Call https::fetch  │  │
                      │  │     (HEAD, ratls=...,  │  │
                      │  │      ca-roots-der=...) │  │
                      │  └─────────┬──────────────┘  │
                      │            │                 │
                      │            ▼                 │
                      │  ┌────────────────────────┐  │
                      │  │ enclave-os egress      │──┼──RA-TLS──►  Remote
                      │  │ client (rustls fork)   │  │             enclave
                      │  │  • verify chain        │  │             under test
                      │  │  • parse quote         │  │
                      │  │  • check measurements  │  │
                      │  │  • check ReportData    │  │
                      │  │  • check OID exts      │  │
                      │  │  • POST quote to       │  │
                      │  │    attestation servers │  │
                      │  └────────────────────────┘  │
                      └──────────────────────────────┘
```

The `verify` function returns a small typed result describing the first
check that failed, or `success = true` when every check passed.

---

## API

### `verify-request`

Only `url` is required.  Every other field narrows the policy: leaving a
field as `none` (or an empty list) means "do not check this property".

| Field | Type | Description |
|---|---|---|
| `url` | `string` | HTTPS URL of the remote enclave (must start with `https://`). |
| `tee` | `option<tee-type>` | `sgx` (default) or `tdx`. |
| `mr-enclave` | `option<list<u8>>` | Expected MRENCLAVE — 32 bytes, SGX only. |
| `mr-signer` | `option<list<u8>>` | Expected MRSIGNER — 32 bytes, SGX only. |
| `mr-td` | `option<list<u8>>` | Expected MRTD — 48 bytes, TDX only. |
| `challenge-nonce` | `option<list<u8>>` | When set, the verifier sends the nonce in TLS extension `0xFFBB` and expects the quote's ReportData to be `SHA-512(SHA-256(pubkey) ‖ nonce)`. When `none`, the deterministic per-TEE binding is reproduced. |
| `oid-requirements` | `option<list<oid-requirement>>` | X.509 extension OIDs that the leaf cert must carry with the exact bytes given. |
| `attestation-servers` | `option<list<string>>` | Attestation-server URLs that **all** must confirm the quote. |
| `ca-roots-der` | `option<list<list<u8>>>` | When `some`, **replaces** the Mozilla root bundle — only the supplied DER-encoded roots are trusted. |

### `verify-result`

| Field | Type | Description |
|---|---|---|
| `success` | `bool` | `true` iff every requested check passed. |
| `error-code` | `option<error-code>` | Failure category — see [error codes](#error-codes). |
| `error-message` | `option<string>` | Free-form detail from the underlying egress client. |
| `target-url` | `string` | Echo of `request.url`. |

### Error codes

| Code | Meaning |
|---|---|
| `invalid-url` | `url` was empty or not `https://`. |
| `connection-failed` | TCP / network failure before TLS started. |
| `tls-chain-invalid` | Chain validation against the trust anchors failed. |
| `quote-missing-or-wrong-tee` | Leaf cert had no attestation extension, or the wrong TEE family. |
| `measurement-mismatch` | One of `mr-enclave` / `mr-signer` / `mr-td` did not match. |
| `report-data-mismatch` | Quote ReportData did not bind the leaf pubkey (and nonce, if set). |
| `oid-mismatch` | A required OID was missing or carried the wrong value. |
| `attestation-server-rejected` | An attestation server refused the quote or was unreachable. |
| `invalid-ca-root` | One of the supplied DER bytes did not parse as a CA cert. |
| `other` | Anything else — see `error-message`. |

---

## Build

```bash
rustup target add wasm32-wasip1
cargo install cargo-component
cargo component build --release
```

Output: `target/wasm32-wasip1/release/enclave_verifier.wasm`

For faster cold start, AOT-compile to `.cwasm`:

```bash
wasmtime compile target/wasm32-wasip1/release/enclave_verifier.wasm \
    -o enclave_verifier.cwasm
```

---

## Deploying

Load the AOT artifact into a running Enclave OS instance over its RA-TLS
control channel exactly like any other WASM app — see the
[wasm-app-example deployment guide](https://github.com/Privasys/wasm-app-example#deployment).

Once loaded, call the `verify` export through the standard `wasm_call`
envelope.  Because the export is tagged `@auth public`, no caller
authentication is required (the **target** enclave's RA-TLS chain is the
trust source — not the caller of this verifier).

---

## License

[AGPL-3.0](LICENSE) — © Privasys.
