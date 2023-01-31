# (Concurrently Secure) Blind-Schnorr-Signatures *[Work in progress]

This repository provides proof-of-concept implementations of Blind Schnorr from https://eprint.iacr.org/2022/1676.pdf in circom. **These implementations are for demonstration purposes only**.  These circuits are not audited, and this is not intended to be used as a library for production-grade applications.

The first concurrently secure blind-signing protocol for Schnorr signatures, using
the standard primitives NIZK and PKE and assuming that Schnorr signatures themselves are
unforgeable. In addition, the paper defines the notion of predicate blind signatures, in which the signer can define a predicate that the blindly signed message must satisfy.

## Benchmark: 

We benchmark the relation using Intel® Core™ i7-10850H CPU @ 2.70GHz × 12 , 31,0 GiB Ram: [^1] 
- NIZK: Groth16 over BN256; The BabyJubJub curve is embedded in the order of BN256;
- message length 256 bit
- The configurations are for the case of 'full blindness'. No predicate check on the message's content is performed.



| PKE: <br> Curve: <br> Schnorr Hash: |  ElGamal[^3] <br>  BabyJubJub <br> Poseidon| ElGamal[^3] <br> BabyJubJub   |  Poseidon  <br>  secp256k1[^2]  <br> SHA256 |   Poseidon <br>  BabyJubJub   <br>  Poseidon   |  ElGamal[^3]  <br>  secp256k1[^2] <br> SHA256|
|---|---|---|---|---|---|
|Constraints                          | 12 377          |107 238    |1 561 618      |  4658         |  1569280 |
|Witness generation                   |  0,016s         |           |  23.933s      | 0,084s  |      23,702s     |
|Proving key size                     |     6,9 MB      |           |               |     3 MB           |    1,1GB      |
|Verification key size                |     4,8 kB      |            |                |      3,8 kB       |  7,5kb   |
|Proving time                         | 0,895s          |    4s     |     38.944s   |  0,654s     |       37,974s  |
|Proof verification time              | 0,399s          |            |            |           0,414s    |     0,416s  |
|Proof size  (public+private)         |                 |            |              |        1,29 kB        |    1,37 kb   |

[^1]: Using [Circom](https://docs.circom.io) 
[^2]: by [0xPARC](https://github.com/0xPARC/ circom-ecdsa)
[^3]: Implemented over the BabyJubJub Curve


