# Known limitations

- Backend matching returns true for any common set bit. This is not proof of a shared encounter and can produce false positives.
- The backend channel has no TLS or upload authentication, and stores filters only in memory without expiry.
- A hash check validates reconstructed content against a received hash; it does not authenticate the sender.
- Identifier rotation alone does not establish unlinkability. Message metadata and stable node identifiers also matter.
- Fake-share injection may prevent valid reconstruction; hash rejection does not prevent denial of service.
- This is an experimental protocol implementation, not a deployment for medical or public-health decisions.

The original algorithm is preserved in this review package so that its limitations remain visible. A corrected matching policy would need an explicit protocol design and new evaluation.
