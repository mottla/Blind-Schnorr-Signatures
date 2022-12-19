# (Concurrently Secure) Blind-Schnorr-Signatures 


The reference implementation of (concurrently secure + predicate) blind Schnorr signatures, as described in https://eprint.iacr.org/2022/1676.pdf.

The first concurrently secure blind-signing protocol for Schnorr signatures, using
the standard primitives NIZK and PKE and assuming that Schnorr signatures themselves are
unforgeable. In addition, the paper defines the notion of predicate blind signatures, in which the signer can define a predicate that the blindly signed message must satisfy.

## Benchmark: 

We implement the relation using:
- NIZK: Groth16 over BN256; 
- PKE: ElGamal over the BabyJubJub curve; 
- message length 256 bit
- Hash: Sha256
- No predicate check is performed

| Compiler | Constraints | Proof Generation Time* |
| ----------- | ----------- | -------- |
| [Circom](https://docs.circom.io) | 72216 | 2.1 sec (via [snarkjs](https://github.com/iden3/snarkjs))|
| [ZoKrates](https://zokrates.github.io/introduction.html) | 107238 | 4.0 sec |

*Intel® Core™ i7-10850H CPU @ 2.70GHz × 12 , 31,0 GiB Ram

