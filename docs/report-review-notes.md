# Review Notes for the Historical DIMY Report

The report documents a coursework prototype and its team diary. It is not a production protocol analysis.

- Rotating an EphID does not prove unlinkability when stable node IDs, timing, addresses, or logs remain observable.
- A broadcast hash verifies consistency with a claimed EphID; it does not authenticate the broadcaster. Forged shares can still poison reconstruction state and cause availability failures.
- Shamir's threshold secrecy depends on a correct scheme and random coefficients. Primitive tests do not establish security of the full advertisement protocol.
- X25519 does not authenticate peers. Its passive confidentiality does not imply resistance to active impersonation.
- Bloom filters have collisions and do not make encounter recovery universally impossible. The overlap matching rule can produce false positives.
- A replay of an identical stored filter need not change a binary any-match result. The original replay discussion overstates the effect without specifying expiry, matching, deduplication, or how stale data becomes newly accepted.
- An HMAC key derived solely from the EphID does not provide an immediately available trusted verifier before reconstruction; after enough shares are observed, it is not a sender-authentication secret. A real design needs an explicit trust and key-distribution model.
- Timestamps require trusted bounds and replay-state handling. Server authentication in TLS does not authenticate a client; client authorization and upload freshness require separate mechanisms.
- The diary credits zdmmhl with the core frontend Task 1-5 flow, security-analysis draft, and integration coordination. The teammate contributed the backend and attacker process.

The historical multi-node runs were not rerun. See the current [limitations](limitations.md) for the published implementation's scope.
