# (Concurrently Secure) Blind-Schnorr-Signatures *[Work in progress]

This repository provides proof-of-concept implementations of Blind Schnorr from https://eprint.iacr.org/2022/1676.pdf in circom. **These implementations are for demonstration purposes only**.  These circuits are not audited, and this is not intended to be used as a library for production-grade applications.

The first concurrently secure blind-signing protocol for Schnorr signatures, using
the standard primitives NIZK and PKE and assuming that Schnorr signatures themselves are
unforgeable. In addition, the paper defines the notion of predicate blind signatures, in which the signer can define a predicate that the blindly signed message must satisfy.


