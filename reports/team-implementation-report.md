# DIMY: Historical Team Implementation Report

> Archival English text edition. Shared two-person coursework, not a production protocol or fresh experiment. Title-page roster and private demo link are omitted. Some original security claims are overbroad: read [report review notes](../docs/report-review-notes.md) and [implementation limitations](../docs/limitations.md). The diary identifies individual responsibilities; backend and attacker work belong to the teammate.

1. How To Run
The implementation contains three executable programs used in the demo: Dimy.py
(frontend nodes), DimyServer.py (backend server), and Attacker.py (Task 11-B
attacker).

Environment requirements:
- Python 3.10+
- cryptography library installed

Run order:
1) Start backend server:
 python3 DimyServer.py
2) Start three normal nodes (official video parameters):
 python3 Dimy.py 18 4 6 40 127.0.0.1 55000 --node-id node1
 python3 Dimy.py 18 4 6 40 127.0.0.1 55000 --node-id node2
 python3 Dimy.py 18 4 6 40 127.0.0.1 55000 --node-id node3
3) Start attacker node for Task 11-B:
 python3 Attacker.py 18 4 6 40 --node-id attacker

For Task 9 (positive upload), type positive in a frontend terminal and press Enter.

2. Executive Summary
This assignment implements a simplified DIMY digital contact tracing protocol using
UDP/TCP sockets in Python. Each node periodically creates a 32-byte EphID, splits it
with k-out-of-n Shamir Secret Sharing, and broadcasts shares over UDP with
probabilistic packet drops. After reconstruction and hash verification, nodes compute an
encounter identifier (EncID) using Diffie-Hellman. EncIDs are encoded into Bloom filters
according to the required lifecycle (DBF, QBF, CBF), and nodes query a backend server
for risk analysis.

The backend server stores CBF uploads from diagnosed users and matches QBF
queries from other users, returning MATCHED or NOT_MATCHED. For security
analysis, we implemented an attacker node that performs fake-share injection on UDP
communication and analyzed a second backend-channel attack scenario (without
implementation) as requested in Task 11.

3. Implementation Discussion and Feature Status

3.1 Task 1-5 (Node-to-node exchange)
- Task 1: 32-byte EphID generation every t seconds (t validated against assignment
range).
- Task 2: k-out-of-n Shamir split of EphID (k>=3, n>=5, k<n enforced).
- Task 3: UDP broadcast sends one share every 3 seconds.
- Task 3a: receiver-side message drop with configured probability p.
- Task 4: EphID reconstruction when at least k unique shares are collected; hash
verification applied.
- Task 5: X25519 Diffie-Hellman to derive shared EncID between nodes.

3.2 Task 6-10 (Bloom filters + backend)
- Task 6: EncID is encoded into current DBF and not retained as plaintext encounter
state.
- Task 7: DBF rotation every t*6 seconds; maximum 6 retained DBFs; older DBFs
removed according to Dt window.
- Task 8: QBF generated every Dt by merging all available DBFs.
- Task 9: diagnosed node uploads merged CBF to backend (triggered by user input
positive). After successful upload, QBF generation is stopped.
- Task 10: node sends QBF via TCP and receives MATCHED/NOT_MATCHED result;
backend performs bit-overlap matching against stored CBFs.

3.3 Task 11 (Security analysis)
A) Security mechanisms in this implementation:
- EphID rotation: Each node generates a fresh X25519 key pair every t seconds, so once
rotated, prior captures cannot be linked to the new identity — preventing long-term
tracking of any individual node.
- Shamir k-out-of-n secret sharing: EphID is split into n shares; at least k are required to
reconstruct. Any fewer than k shares reveal nothing (information-theoretic security), so
an eavesdropper or a node that misses shares due to packet loss cannot recover the
EphID.
- SHA-256 hash verification: The hash of the EphID is broadcast as a commitment
alongside each share, and verified after reconstruction, ensuring any tampered or forged
share produces a mismatch and the encounter is rejected — directly countering
fake-share injection.
- Diffie-Hellman key exchange (X25519): The EncID is derived locally from the shared
secret and never transmitted, so a full passive observer of all UDP traffic still cannot
learn it.
- Bloom filters (DBF / QBF / CBF): EncIDs are stored as bit-patterns rather than plaintext,
making individual encounters unrecoverable from the filter while still enabling server-side
risk matching via bitwise AND.

B) Implemented attack (Task 11-B): Fake Share Injection.
The attacker sniffs UDP broadcasts and quickly injects forged shares for observed
(sender_id, ephid_hash). Victim nodes may store fake x-shares first, causing
reconstruction/hash failure and loss of legitimate encounters.

C) Backend-channel attack analysis (Task 11-C, analysis only):
Since node-to-server TCP communication is unencrypted and unauthenticated, an
attacker on the same local network can capture a CBF upload in plaintext as it is
transmitted. The attacker then replays this captured CBF to the server in a new TCP
connection, presenting it as a fresh upload from a diagnosed user.


The server has no mechanism to verify the authenticity or freshness of an incoming CBF,
it accepts any well-formed upload and appends it to its stored list. The replayed CBF
now participates in all subsequent QBF matching. Any node that has ever shared a
bit-pattern with the original diagnosed user, including nodes that have since recovered or
were never actually exposed, will receive a false MATCHED result. This directly corrupts
the risk-analysis function that DIMY is built on: users are incorrectly notified of exposure,
eroding trust in the system and potentially causing unnecessary isolation or panic. The
attacker requires no credentials and needs only a single captured packet to trigger this
effect indefinitely.

D) Suggested countermeasures (Task 11-D):
- HMAC on UDP shares (for 11b): Each share carries an HMAC derived from the EphID,
so only the legitimate sender who holds the actual EphID can produce a valid tag. A
forged share with a random y-vector cannot pass verification, closing the fake-share
injection window entirely.
- Timestamp freshness window (for 11b): Each share includes a timestamp; receivers
reject shares outside a short freshness window, removing the attacker's ability to replay
previously captured legitimate shares to pollute reconstruction state.
- TLS for node-to-server TCP (for 11c): Encrypting the channel removes the plaintext
visibility that makes CBF capture possible in the first place. Combined with server-side
certificate authentication, replayed connections from unauthorised clients can be
rejected before any data is accepted.
- CBF upload authentication and deduplication (for 11c): The server should require each
CBF upload to carry a one-time token (e.g., issued after a positive diagnosis is
confirmed), and reject uploads bearing tokens that have already been used. This
ensures each CBF is accepted exactly once, neutralising replay regardless of whether
the channel is encrypted.

4. Design Trade-offs, Special Points, and Possible Improvements
Trade-offs considered
- UDP broadcast was chosen to align with assignment constraints and emulate proximity
advertisement, but reliability is intentionally reduced by packet drops.
- Bloom filter matching uses a lightweight overlap rule for fast demo-time response; this
favors simplicity over richer epidemiological scoring.
- For demo clarity, debug logs are extensive; production-style deployment would reduce
output verbosity.

What is special in our implementation
- End-to-end pipeline from EphID exchange to backend risk result is integrated in one
frontend program.
- Assignment-specific timing model (t, DBF rotation, Dt query) is implemented directly
from the modified specification.
- A concrete attacker process is provided and can be demonstrated live with visible
effect on reconstruction outcomes.

Improvements and extensions
- Add authenticated share advertisements to prevent spoofed injection.
- Use robust encounter session binding to reduce false negatives under asynchronous
EphID rotations.
- Enhance backend matching policy and maintain audit logs for verification.

- Add experiment scripts for repeatable evaluation across different p, k, n, t values.

5. Code Borrowing Declaration

In this assignment, we did not borrow any codes from Web. All the codes were written by
our group members. The GenAI tools are only used for report translation and diary
organization.

6. Assignment Diary

Week 6
- Jiawei Dong: Reviewed DIMY paper and assignment constraints; drafted message
format and process layout.
- Shaoran Liu: Set up local test environment and validated UDP/TCP communication
baseline.

Week 7
- Jiawei Dong: Implemented Task 1-5 core flow (EphID, Shamir, UDP broadcast/drop,
reconstruction, DH EncID).
- Shaoran Liu: Built backend server skeleton and TCP framed messaging utilities.

Week 8
- Jiawei Dong: Keep on implementing Task 1-5.
- Shaoran Liu: Completed server-side CBF storage and QBF matching; integrated with
frontend queries.

Week 9
- Jiawei Dong: Wrote Task 11 security analysis and countermeasure section draft;
coordinated integration testing.
- Shaoran Liu: Implemented attacker node (fake share injection) and attack
demonstration scripts.

Week 10
- Jiawei Dong + Shaoran Liu: Final parameter validation (`t=18, k=4, n=6, p=40`), demo
video recording, report polishing, and submission packaging. 