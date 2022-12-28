
//code by Mottla so dont trust it. Not sufficiently testet!!
//secp256k1 curve and big int implementation 0xPARC's https://github.com/0xPARC/circom-ecdsa
pragma circom 2.1.2;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";
include "secp256k1_non_native_modP/bigint.circom";
include "secp256k1_non_native_modP/secp256k1.circom";
include "secp256k1_non_native_modP/bigint_func.circom";
include "secp256k1_non_native_modP/ecdsa_func.circom";
include "secp256k1_non_native_modP/ecdsa.circom";
include "secp256k1_non_native_modP/secp256k1_func.circom";
include "secp256k1_non_native_modP/secp256k1_utils.circom";
include "circomlib/circuits/sha256/sha256.circom";


template Main(n,k) {
    signal input X[2][k];
    signal input R[2][k];
    signal input cc[k];
    signal input Cmsg;
    signal input msg;
    signal input alpha[k];
    signal input beta[k];
    signal input rho;
    var bitLength = n*k;
    //somehow they reserve 100 slots but only write into first k.. 
    
    //check that Cmsg == H(alpha,beta,msg,rho)
    //we take poseidon for the commitment
    //we combine 2 chuncks.. but this saves only 150 constraints.. so worth it?
    component hash2 = Poseidon(6);
    hash2.inputs[0] <== (alpha[0]+(alpha[1]*(1<<n)));
    hash2.inputs[1] <== (alpha[2]+(alpha[3]*(1<<n)));
    hash2.inputs[2] <== (beta[0]+(beta[1]*(1<<n)));
    hash2.inputs[3] <== (beta[2]+(beta[3]*(1<<n)));
    hash2.inputs[4] <== msg;
    hash2.inputs[5] <== rho;
    log(hash2.out);
    Cmsg === hash2.out; 


    //compute alpha *G 
    component g_mult = ECDSAPrivToPub(n, k);
    for (var idx = 0; idx < k; idx++) {
        g_mult.privkey[idx] <== alpha[idx];
    }
    // compute beta * X
    component pubkey_mult = Secp256k1ScalarMult(n, k);
    for (var idx = 0; idx < k; idx++) {
        pubkey_mult.scalar[idx] <== beta[idx];
        pubkey_mult.point[0][idx] <== X[0][idx];
        pubkey_mult.point[1][idx] <== X[1][idx];
    }

    // compute S = alpha* G + beta * X
    //Should we check that the points are unequal??
    component sum_res = Secp256k1AddUnequal(n, k);
    for (var idx = 0; idx < k; idx++) {
        sum_res.a[0][idx] <== g_mult.pubkey[0][idx];
        sum_res.a[1][idx] <== g_mult.pubkey[1][idx];
        sum_res.b[0][idx] <== pubkey_mult.out[0][idx];
        sum_res.b[1][idx] <== pubkey_mult.out[1][idx];
    }

      // compute R' = S + R
    component sum_res2 = Secp256k1AddUnequal(n, k);
    for (var idx = 0; idx < k; idx++) {
        sum_res2.a[0][idx] <== sum_res.out[0][idx];
        sum_res2.a[1][idx] <== sum_res.out[1][idx];
        sum_res2.b[0][idx] <== R[0][idx];
        sum_res2.b[1][idx] <== R[1][idx];
    }

    //prepare to create the Schnorr challenge c = H(R,X,m) using SHA256
    component hash = Sha256(bitLength*3);
    
    //write the x coordinate of R' into the hash input
    component R_x_bits[k];   
    for (var idx = 0; idx < k; idx++) {
        R_x_bits[idx] = Num2Bits(n);    
        sum_res.out[0][idx] ==> R_x_bits[idx].in;
        for (var i=0; i<n; i++) {
            R_x_bits[idx].out[i] ==> hash.in[i+n*idx];
        }
    } 
    //Write the public key X's x-coordinate into the hash input
    component X_x_bits[k];   
    for (var idx = 0; idx < k; idx++) {
        X_x_bits[idx] = Num2Bits(n);    
        X[0][idx] ==> X_x_bits[idx].in;
        for (var i=0; i<n; i++) {
            X_x_bits[idx].out[i] ==> hash.in[bitLength+i+n*idx];
        }
    } 

    //write the message m into the hash input
    component msgbits = Num2Bits(bitLength);    
    msg ==> msgbits.in;
    for  (var i=0; i<bitLength; i++) {
        msgbits.out[i] ==> hash.in[(bitLength*2)+i];
    }

 
    //split the hash output into 4x64 bit chuncks
    component fin[k];
    for (var idx = 0; idx < k; idx++) {
        fin[idx] = Bits2Num(n);
        for (var i=0; i<n; i++) {
            hash.out[i+n*idx] ==> fin[idx].in[i];
        }
    }
    
        //NOTE that we mod the order, not the prime!
    var q[100] = get_secp256k1_order(n, k);
    //perform addition mod q
    //TODO mod reduce.. 
    component big_add = BigAddModP(n, k);
    for (var i = 0; i < k; i++) {
        big_add.a[i] <== fin[i].out;
        big_add.b[i] <== beta[i];
        big_add.p[i] <== q[i];
    }  


    //assert that statment cc ==  H(R,X,m) + beta mod p
    for (var idx = 0; idx < k; idx++) {
        log(big_add.out[idx]);
        cc[idx] === big_add.out[idx];
    }   
    
    

}



component main {public [X,R,cc,Cmsg]}= Main(64,4);