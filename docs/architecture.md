# Architecture

```text
rotating X25519 public key -> Shamir shares -> UDP advertisement
received shares -> reconstruction + hash check -> X25519 encounter ID
encounter ID -> current DBF -> rotated DBFs -> QBF/CBF
QBF query or positive CBF upload -> length-prefixed JSON/TCP -> backend
```

The selected frontend is the non-demo file from `dimytotal`, with a consistent filename in its usage header. The supplied report documents three-node demonstrations; those runs were not repeated here.
