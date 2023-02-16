
//code by Mottla so dont trust it. Not sufficiently testet!!
//secp256k1 curve and big int implementation 0xPARC's https://github.com/0xPARC/circom-ecdsa
pragma circom 2.1.2;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/escalarmulany.circom";
include "secp256k1_non_native_modP/bigint.circom";
include "secp256k1_non_native_modP/secp256k1.circom";
include "secp256k1_non_native_modP/bigint_func.circom";
include "secp256k1_non_native_modP/ecdsa_func.circom";
include "secp256k1_non_native_modP/ecdsa.circom";
include "secp256k1_non_native_modP/secp256k1_func.circom";
include "secp256k1_non_native_modP/secp256k1_utils.circom";
include "circomlib/circuits/sha256/sha256.circom";


template SplitIntoChunks(n) {
    signal input in;
    signal output out[4];

    out[0] <-- in % (1 << n);
    var a = (in \ (1 << n)) ;
    out[1] <-- a % (1 << n);
    a = (a \ (1 << n)) ;
    out[2] <-- a  % (1 << n);
    a = (a \ (1 << n)) ;
    out[3] <--  a  % (1 << n);

    in === out[0] + out[1]* (1 << n) + out[2]* (1 << (n*2)) +   out[3]* (1 << (n*3)) ;
}

template Main(n,k) {
    signal input X[2][k];
    signal input R[2][k];
    signal input cc[k];
    signal input Cmsg;
    signal input C0[2];  
    signal input ek[2];
    signal input msg;
    signal input rho;
    var bitLength = n*k;
    //somehow they reserve 100 slots but only write into first k.. 
    
 
    var bits = 251; //the order r of the babyjub curve is 251 bits. 
    var i;
    var base[2] = [5299619240641551281634865583518297030282874472190772894086521144482721001553,
            16950150798460657717958625567821834550301663161624707787222815936182638968203];   

    //ElGamal Enc
    // H(h^rho1) + msg == c1
    component n2b_rho1= Num2Bits(251);  //a field element has 254 bit, but we only care about the 251 first bits. Revisit this point and rethink
   
    //h^rho1
    component ek_rho1 = EscalarMulAny(251);
    ek_rho1.p[0] <== ek[0];
    ek_rho1.p[1] <== ek[1];
    
    rho ==> n2b_rho1.in;

     // C_0 == g^rho
    component g_pow_rho = EscalarMulFix(251,base); 

    for  (i=0; i < 251; i++) {
        n2b_rho1.out[i] ==> ek_rho1.e[i];
        n2b_rho1.out[i] ==> g_pow_rho.e[i];
    }       

    log("comparing C0");
    log(g_pow_rho.out[0]);
    log(g_pow_rho.out[1]);
    C0[0] ===  g_pow_rho.out[0];
    C0[1] ===  g_pow_rho.out[1];

    //hash alpha and beta group elements to obtain uniform blinding factors
    component pEx = PoseidonEx(2, 3);
    pEx.initialState <== 0;  //Why setting it to 0.. need to read the paper
    pEx.inputs[0] <== ek_rho1.out[0];
    pEx.inputs[1] <== ek_rho1.out[1];  //we might not need to do this.. too little entropy anyway?
    

    log("hashed alpha");
    log(pEx.out[0]);
    log("hashed beta");
    log(pEx.out[1]);
    log("hashed message blinding");
    log(pEx.out[2]);    
    log("assert encryption of message is equal to the provided ciphertext");   
    log(msg+pEx.out[2]);
 
    Cmsg === msg+pEx.out[2]; 


    component splitteralpha = SplitIntoChunks(64);
    splitteralpha.in <== pEx.out[0];
    component splitterbeta = SplitIntoChunks(64);
    splitterbeta.in <== pEx.out[1];

    //compute alpha *G 
    component g_mult = ECDSAPrivToPub(n, k);
    for (var idx = 0; idx < k; idx++) {
        g_mult.privkey[idx] <== splitteralpha.out[idx];
    }
    // compute beta * X
    component pubkey_mult = Secp256k1ScalarMult(n, k);
    for (var idx = 0; idx < k; idx++) {
        pubkey_mult.scalar[idx] <== splitterbeta.out[idx];
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
        big_add.b[i] <== splitterbeta.out[i];
        big_add.p[i] <== q[i];
    }  


    //assert that statment cc ==  H(R,X,m) + beta mod p
    log(big_add.out[0]);
    log(big_add.out[1]);
    log(big_add.out[2]);
    log(big_add.out[3]);
    for (var idx = 0; idx < k; idx++) {        
        cc[idx] === big_add.out[idx];
    }       

}



component main {public [X,R,cc,Cmsg,C0]}= Main(64,4);
