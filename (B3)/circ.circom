
//code by Mottla so dont trust it. Not sufficiently testet!!
//secp256k1 curve and big int implementation 0xPARC's https://github.com/0xPARC/circom-ecdsa
pragma circom 2.1.2;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/multiplexer.circom";
include "circomlib/circuits/babyjub.circom";
include "circomlib/circuits/escalarmulany.circom";
include "circomlib/circuits/escalarmulfix.circom";
include "circomlib/circuits/sha256/sha256.circom";




template Main() {
    signal input X[2];
    signal input R[2];
    signal input cc;
    signal input C0[2];
    signal input Cmsg;
    signal input ek[2];
    signal input pred;
    signal input msgToSign;
    signal input witness[8];
    signal input rho; 
    //somehow they reserve 100 slots but only write into first k.. 
    
 
    var bits = 254; //the order r of the babyjub curve is 251 bits. 
    var i;
    var base[2] = [5299619240641551281634865583518297030282874472190772894086521144482721001553,
            16950150798460657717958625567821834550301663161624707787222815936182638968203]; 


    component hashWitness = Sha256(bits*8);
    component witnessBits[8]; 
    for  (var i=0; i<8; i++) {
        witnessBits[i] = Num2Bits(bits); 
        witness[i] ==> witnessBits[i].in;
        for  (var j=0; j < bits; j++) {
            witnessBits[i].out[j] ==> hashWitness.in[i*bits+j];
        }
    }
    
    component hashVal = Bits2Num(bits);    
    for  (var j=0; j < bits; j++) {
        hashVal.in[j] <== hashWitness.out[j];
    }    
    log("hash witness");
    log(hashVal.out);
    hashVal.out === msgToSign;            

    component tx = Bits2Num(16);    
    for  (var j=0; j < 16; j++) {
        tx.in[j] <== witnessBits[1].out[j];
    }    
    log("tx value");
    log(tx.out);
    log("pred value");
    log(pred);
    component leq = LessEqThan(16);
    leq.in[0] <== tx.out;
    leq.in[1] <== pred;
    log("comparing value < pred:");
    log(leq.out);
    1 === leq.out;
  
    //ElGamal Enc
    component n2b_rho1= Num2Bits(bits);  //a field element has 254 bit, but we only care about the 251 first bits. Revisit this point and rethink
    rho ==> n2b_rho1.in;

    // C_0 == g^rho
    component g_pow_rho = EscalarMulFix(bits,base);    
    for  (i=0; i < bits; i++) {
        n2b_rho1.out[i] ==> g_pow_rho.e[i];
    }
    log("comparing C0");
    log(g_pow_rho.out[0]);
    log(g_pow_rho.out[1]);
    C0[0] ===  g_pow_rho.out[0];
    C0[1] ===  g_pow_rho.out[1];

    // H(ek^rho) + msg == c1
    component ek_rho1 = EscalarMulAny(bits);
    ek_rho1.p[0] <== ek[0];
    ek_rho1.p[1] <== ek[1];
    for  (i=0; i < bits; i++) {
        n2b_rho1.out[i] ==> ek_rho1.e[i];
    }
   
    
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
    log(msgToSign+pEx.out[2]);
 
    Cmsg === msgToSign+pEx.out[2]; 


     //compute alpha*G
    component n2b_alpha = Num2Bits(bits);
    pEx.out[0] ==> n2b_alpha.in;
    component alpha_G = EscalarMulFix(bits,base);    
    for  (i=0; i<bits; i++) {
        n2b_alpha.out[i] ==> alpha_G.e[i];
    }

    //compute beta*X
    component n2b_beta = Num2Bits(bits);
    pEx.out[1] ==> n2b_beta.in;
    component beta_X = EscalarMulAny(bits);
    beta_X.p[0] <== X[0];
    beta_X.p[1] <== X[1];   
    for  (i=0; i<bits; i++) {
        n2b_beta.out[i] ==> beta_X.e[i];
    }

    // R'' = aG+bX
    component add1 = BabyAdd();
    add1.x1 <== alpha_G.out[0];
    add1.y1 <== alpha_G.out[1];
    add1.x2 <== beta_X.out[0];
    add1.y2 <== beta_X.out[1];
	
    component add2 = BabyAdd();
    add2.x1 <== add1.xout;
    add2.y1 <== add1.yout;
    add2.x2 <== R[0];
    add2.y2 <== R[1];



    //prepare to create the Schnorr challenge c = H(R,X,m) using SHA256
    component hash = Sha256(bits*3);

    //write the x coordinate of R' into the hash input
     //write the message m into the hash input
    component Rbits = Num2Bits(bits);    
    add2.xout ==> Rbits.in;
    for  (var i=0; i<bits; i++) {
        Rbits.out[i] ==> hash.in[i];
    }   
    //Write the public key X's x-coordinate into the hash input
     //write the message m into the hash input
    for  (var i=0; i<bits; i++) {
        n2b_beta.out[i] ==> hash.in[bits + i];
    }   

    //write the message m into the hash input
    for  (var i=0; i<bits; i++) {
        hashWitness.out[i] ==> hash.in[(bits*2)+i];
    }   
    component hashVal2 = Bits2Num(bits);    
    for  (var j=0; j < bits; j++) {
        hashVal2.in[j] <== hash.out[j];
    } 

    //assert that statment cc ==  H(R,X,m) + beta mod p
    log("final hash");
    log(hashVal2.out+pEx.out[1]);

    hashVal2.out+pEx.out[1] === cc;

}



component main {public [X,R,cc,pred,C0,Cmsg]}= Main();
