# DIMY Contact-Tracing Lab

A Python coursework prototype connecting rotating identifiers, Shamir sharing, X25519 encounter identifiers, Bloom filters, and a TCP backend.

## Components

- `Dimy.py`: frontend node, identifier exchange and filter lifecycle.
- `DimyServer.py`: in-memory filter upload/query service.
- `Attacker.py`: team lab demonstration of fake-share injection.

## Local lab setup

Python 3.10+ and `cryptography` are required. In an isolated lab with UDP broadcast support:

```bash
python -m pip install -r requirements.txt
python DimyServer.py --host 127.0.0.1 --port 55000
python Dimy.py 18 4 6 40 127.0.0.1 55000 --node-id node1
```

Start additional nodes with different node IDs. The frontend broadcasts on the lab network; it is not restricted to loopback by the server bind address. The multi-node protocol has not been rerun.

See [architecture](docs/architecture.md) and [limitations](docs/limitations.md).


## Provenance

Developed for UNSW COMP4337/9337 as a team assignment. The assignment diary credits zdmmhl with the Task 1–5 core flow, the security-analysis draft, and integration-test coordination; backend and attacker contributions belong to the teammate.

## Verification status

Four network-free unit tests passed on 8 October 2026 with Python 3.12: threshold-subset reconstruction, Bloom-filter merging, serialization and identical-filter backend matching. Run `python -m unittest discover -s tests -v`. False-positive rates and the multi-node protocol have not been validated.

