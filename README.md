# (Concurrently Secure) Blind-Schnorr-Signatures *[Work in progress]

This repository provides proof-of-concept implementations of Blind Schnorr from https://eprint.iacr.org/2022/1676.pdf in circom. **These implementations are for demonstration purposes only**.  These circuits are not audited, and this is not intended to be used as a library for production-grade applications.

The first concurrently secure blind-signing protocol for Schnorr signatures, using
the standard primitives NIZK and PKE and assuming that Schnorr signatures themselves are
unforgeable. In addition, the paper defines the notion of predicate blind signatures, in which the signer can define a predicate that the blindly signed message must satisfy.

## Benchmark: 

We benchmark the relation using Intel® Core™ i7-10850H CPU @ 2.70GHz × 12 , 31,0 GiB Ram:
- NIZK: Groth16 over BN256; The BabyJubJub curve is embedded in the order of BN256;
- message length 256 bit
- No predicate check on the message is performed, as suggested in the paper 



|| PKE: ElGamal <br> Curve: BabyJubJub [^1] | PKE: ElGamal <br> Curve: BabyJubJub  [^2] | PKE: Poseidon [^3] <br> Curve: secp256k1 by [0xPARC](https://github.com/0xPARC/circom-ecdsa)|
|---|---|---|---|
|Constraints                          |72 216    |107 238 |1 561 618 |
|Circuit compilation                  |         |       |           |
|Witness generation                   |         |       |  23.933s  |
|Proving key size                     |         |       |           |
|Proving key verification             |         |       |           |
|Proving time                         |2.1s     |    4s   |     38.944s  |
|Proof verification time              |         |       |            |


[^1]: Using [Circom](https://docs.circom.io) 
[^2]: Using [ZoKrates](https://zokrates.github.io/introduction.html)
[^3]: We relax the requirement and use a commitment scheme instead of a PKE. This works fine in the ROM and does not affect security (putting some details under the rug)


