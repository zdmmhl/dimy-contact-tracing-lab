# Historical Frontend Run Evidence

> Original Task 1-5 run narrative. The multi-node protocol was not rerun during publication. These observations are not a security proof.

# DIMY Frontend (Task 1-5) Run Write-up

## Test Setup

- Environment: Kali Linux
- Program: `Dimy.py`
- Example commands used:
  - `python3 Dimy.py 15 3 5 50 --node-id node1`
  - `python3 Dimy.py 15 3 5 50 --node-id node2`
  - `python3 Dimy.py 30 3 5 30 --node-id node1`
  - `python3 Dimy.py 30 3 5 30 --node-id node2`
- Multi-node test performed with at least node1 and node2 (and one run including node3 traffic).

## Task 1: EphID Generation

### Evidence observed

- Repeated logs such as:
  - `New EphID generated | hash=25a01b0357f1... | t=15s | bytes=32`
  - `New EphID generated | hash=436950267815... | t=15s | bytes=32`
  - `New EphID generated | hash=250c928727fc... | t=30s | bytes=32`

### Result

- 32-byte EphID is generated periodically according to input `t` (verified with both `t=15` and `t=30`).

## Task 2: k-out-of-n Shamir Sharing

### Evidence observed

- Logs after each new EphID:
  - `Created 5 shares using 3-out-of-5 Shamir Secret Sharing`

### Result

- For each EphID, the program correctly creates `n=5` shares with threshold `k=3`.

## Task 3: Share Broadcast Every 3 Seconds

### Evidence observed

- Sequential sending logs:
  - `Sent share 1/5 ...`
  - `Sent share 2/5 ...`
  - ...
  - `Sent share 5/5 ...`
- Followed by:
  - `All 5 unique shares sent for EphID ..., waiting for next EphID`

### Result

- Shares are broadcast one-by-one in order and complete one cycle per EphID.

## Task 3a: Message Drop Mechanism

### Evidence observed

- Drop logs appeared during receiving:
  - `Dropped message from node3 for EphID ...`
  - `Dropped message from node2 for EphID ...`

### Result

- Probabilistic drop mechanism is active and affects incoming shares as required.

## Task 4: EphID Reconstruction and Hash Verification

### Evidence observed

- When enough shares were collected:
  - `shares=3/3`
  - `Attempting EphID reconstruction for sender=node2 using 3 shares`
  - `Hash verification PASSED for sender=node2 | EphID hash=...`

### Result

- Node reconstructs peer EphID after receiving at least `k` shares and verifies it using hash comparison.

## Task 5: Diffie-Hellman Encounter ID (EncID)

### Evidence observed

- Logs showing DH-based EncID computation:
  - `EncID computed via DH | peer=node2 | local=250c9287... peer=6287e4bc...`
  - `EncID=2362c6a8823780bd4c3940df875fb842926aff0aaf1a1fed561420265b729266`

- Matching EncID observed on the other node for reversed local/peer pair:
  - `EncID computed via DH | peer=node1 | local=6287e4bc... peer=250c9287...`
  - `EncID=2362c6a8823780bd4c3940df875fb842926aff0aaf1a1fed561420265b729266`

- Second matching pair also observed:
  - node1: local `7e682fc7...`, peer `12a7c252...`, EncID `14f7a5fa10643ed2...`
  - node2: local `12a7c252...`, peer `7e682fc7...`, EncID `14f7a5fa10643ed2...`

### Result

- Diffie-Hellman exchange produces shared EncID values consistently across both participants for the same encounter pair.

## Summary

- Tasks 1-5 were functionally validated in Kali Linux multi-node runs.
- Required behaviors (periodic EphID generation, Shamir sharing, UDP share exchange with drops, reconstruction+hash check, and DH EncID agreement) were all observed in terminal outputs.
