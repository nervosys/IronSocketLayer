# IronSocketLayer and wolfSSL

wolfSSL is a mature, widely deployed C TLS library with a small footprint, a
FIPS 140-3 validated cryptographic module (wolfCrypt) and a commercial DO-178C
DAL-A offering. It is the reference point for embedded and certified TLS. This
document compares the two honestly: where IronSocketLayer is designed to be the
better choice for **agentic applications**, and where wolfSSL is ahead today.

No speed comparison with wolfSSL is made, because none has been measured. A
claim about speed without a controlled measurement would be the kind of
unchecked assertion this project refuses elsewhere. Against rustls with *ring*,
which has been measured ([bench/](../bench/README.md)), IronSocketLayer is
slower: about 0.7× the full-handshake rate and 0.5× bulk throughput, with resumption level. The
causes are IronCrypto's P-256 and AES-GCM speed, not the protocol layer.
wolfSSL's assembly-optimised wolfCrypt should be expected to be ahead as well.

## Where IronSocketLayer is designed to win

| | IronSocketLayer | wolfSSL |
|---|---|---|
| **Machine-readable knowledge** | An ontology of every protocol element, error, profile and intent, exported as JSON-LD and OWL, linked into IronCrypto's algorithm ontology. It is held equal to the code by tests. | Human documentation and a C API. |
| **Configuration by intent** | `recommend(intent, policy)` returns a profile with rationale, rejected alternatives and constraints, and says *unavailable* rather than substituting. | The caller chooses cipher lists and options. |
| **Knowing what a session provides** | `SessionReport` lists the properties that hold (post-quantum key exchange, post-quantum authentication across the whole chain, mutual authentication, FIPS-approved algorithms) with stable ids and a typed event trail. | The caller queries individual parameters and infers properties. |
| **Actionable errors** | Closed `ErrorKind` with a stable id, alert mapping, `retryable` / `caller_correctable` / `peer_fault`, and recovery steps in the ontology. | Integer error codes and strings. |
| **Agent tool interface** | Built-in MCP server: ontology queries, recommender, error explanations, self-tests, live `tls_probe`. | None. |
| **Verification cannot be switched off** | No such API exists; public-key pinning is provided for PKI-less peers. | `SSL_VERIFY_NONE` exists, an easy fallback for an agent that meets a certificate error. |
| **Post-quantum by default** | The default profile leads with X25519MLKEM768; the post-quantum profile refuses classical-only peers; ML-DSA-65 end to end for authentication. | Supported (ML-KEM and ML-DSA); whether it is offered depends on build and runtime configuration. |
| **Memory safety** | Rust with `#![forbid(unsafe_code)]` in the protocol layer. | C; memory safety rests on review, testing and fuzzing. |
| **Requirements traceability** | Tagged LLRs traced to tests, with the matrix enforced by a test. | Provided as part of the commercial DO-178C package. |
| **Architecture** | Sans-I/O engine shared by TCP and QUIC; `no_std`. | Callback-based I/O; very broad platform support. |

## Where wolfSSL is ahead

| | wolfSSL | IronSocketLayer |
|---|---|---|
| **FIPS 140-3** | wolfCrypt holds CMVP validation. | Not validated. The gate and indicators are in place, and validation would require IronCrypto's submission. |
| **DO-178C** | wolfSSL offers a commercial DAL-A certification package for wolfCrypt. | Not certified. The profile, requirements trace and tests support a certification effort; plans, MC/DC evidence, tool qualification and independence remain (see [DO-178C.md](DO-178C.md)). |
| **Protocol breadth** | TLS 1.2, DTLS 1.2/1.3, session resumption, 0-RTT, OCSP and CRL, ECH, many more cipher suites and extensions. | TLS 1.3 and QUIC-TLS only (TLS 1.2 excluded by design); session resumption (PSK with (EC)DHE), OCSP stapling, CRLs, record_size_limit, Encrypted Client Hello and opt-in 0-RTT (TLS over TCP and QUIC) are implemented. Staples IronSocketLayer mints use SHA-256 CertIDs, which clients that look up only by SHA-1 do not match. |
| **Maturity** | Long deployment history, a CVE process, extensive third-party review. | New code. Interop against Cloudflare, Google, GitHub and OpenSSL 3.5 is tested, but there is no field history. |
| **Footprint and hardware** | Tuned for very small targets, with hardware crypto acceleration across many vendors. | Not yet measured for size. Uses IronCrypto's AES-NI and CLMUL paths on x86-64 (its ARMv8 backend is not yet enabled by default); `alloc` required. |
| **Speed** | Assembly-optimised wolfCrypt (not measured here). | Measured only against rustls/ring: about 0.7× the full-handshake rate and 0.5× the bulk throughput, with resumption level. The causes are IronCrypto's P-256 (3–4× slower than ring) and AES-GCM (about 2.6×). The record layer reaches 73–87% of the cipher's ceiling. |
| **Parameter sets** | ML-KEM-512/768/1024, ML-DSA-44/65/87. | ML-KEM-768/1024 and ML-DSA-65/87, which is enough for CNSA 2.0 (`profile:cnsa-2`). The 512 and 44 sets are not offered. |

## Choosing

* An agent, or a system of agents, that must configure, verify and explain
  its own secure channels, especially with post-quantum or mutual-TLS
  requirements: IronSocketLayer is built for this.
* A certified deliverable needed now, TLS 1.2 or DTLS, or the smallest
  possible footprint on a microcontroller: wolfSSL.
