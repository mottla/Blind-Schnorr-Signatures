
//code by Mottla so dont trust it. Not sufficiently testet!!
// THIS PROJECT REquires https://github.com/personaelabs/spartan-ecdsa 
// circom with secq256k1 scalar field support 
pragma circom 2.1.2;

include "../circomlib/circuits/poseidon.circom";
include "../circomlib/circuits/comparators.circom";
include "../circomlib/circuits/multiplexer.circom";
include "../circomlib/circuits/sha256/sha256.circom";
include "../secp256k1/mul.circom";
include "../circomlib/circuits/bitify.circom";
include "../circomlib/circuits/gates.circom";



template Main(n) {
    //Note that the verifier must check that X, R,C,ek are valid curve points out
    signal input X[2];
    signal input R[2];
    //the verifier checks that c is < q outside
    signal input c;
    signal input pred;
    signal input Cmsg;
    signal input C0[2];  
    signal input ek[2];
    //private inputs
    signal input rho;
    signal input witness[n];

    var bitLength = 256;
    var G[2] = [65485170049033141755572552932091555440395722142984193594072873483228125624049,
            73163377763031141032501259779738441094247887834941211187427503803434828368457]; 

     log("start");
    //hash the transaction
    component hashWitness = Sha256(bitLength*n);
    component witnessBits[n]; 
    for  (var i=0; i<n; i++) {
        witnessBits[i] = Num2Bits(bitLength); 
        witness[i] ==> witnessBits[i].in;
        for  (var j=0; j < bitLength; j++) {
            witnessBits[i].out[j] ==> hashWitness.in[i*bitLength+j];
        }
    }    
    component hashVal = Bits2Num(bitLength);    
    for  (var j=0; j < bitLength; j++) {
        hashVal.in[j] <== hashWitness.out[j];
    }    
    log("sha256 hashed transaction value:");
    var msg = hashVal.out;
    log(hashVal.out);         

    //now do some artificial predicate check
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
  
    log("start DHIES");
    // check if H(ek^rho) + msg == c1   
    // DHIES: to encrypt msg under public key ek, sample rho, and blind msg with H(ek^rho)   
    component ek_rho = Secp256k1Mul();
    ek_rho.scalar <== rho;
    ek_rho.xP <== ek[0];
    ek_rho.yP <== ek[1];

    
    // C_0 == g^rho     //proof knowledge of the secret key rho
    component g_pow_rho = Secp256k1Mul();    
    g_pow_rho.scalar <== rho;
    g_pow_rho.xP <== G[0];
    g_pow_rho.yP <== G[1];
    log("comparing C0");
    log(g_pow_rho.outX);
    log(g_pow_rho.outY);
    C0[0] ===  g_pow_rho.outX;
    C0[1] ===  g_pow_rho.outY;


    log("start hash");
     // H(X^rho) 
    //hash alpha and beta group elements to obtain uniform blinding factors
    component pEx = PoseidonEx(2, 3);   //it seems that we cant squeeze as many times we want in the current circom implementation. Optimize this later
    pEx.initialState <== 0;  //Why setting it to 0.. need to read the paper
    pEx.inputs[0] <== ek_rho.outX;  //absorb the X and Y coordinate
    pEx.inputs[1] <== ek_rho.outY;
    

    log("hashed alpha");
    log(pEx.out[0]);
    var alpha = pEx.out[0];
    log("hashed beta");
    log(pEx.out[1]);
    var beta = pEx.out[2];
    log("hashed message blinding");
    log(pEx.out[2]);    
    log("assert encryption of message is equal to the provided ciphertext");   
    log(msg+pEx.out[2]);
     // H(ek^rho) + msg == c1
    Cmsg === msg+pEx.out[2]; 
 

     //now lets do the Schnorr stuff. 
     //compute alpha*G   
    component alpha_G = Secp256k1Mul();
  
    alpha_G.scalar <== alpha;
    alpha_G.xP <== G[0];
    alpha_G.yP <== G[1];
    
    //compute beta*X   
    component beta_X  = Secp256k1Mul();
  
    beta_X.scalar <== beta;
    beta_X.xP <== X[0];
    beta_X.yP <== X[1];

    // R'' = aG+bX
    component add1 = Secp256k1AddComplete();
    add1.xP <== alpha_G.outX;
    add1.yP <== alpha_G.outY;
    add1.xQ <== beta_X.outX;
    add1.yQ <== beta_X.outY;
    
        // R' = R+R''
    component add2 = Secp256k1AddComplete();
    add2.xP <== add1.outX;
    add2.yP <== add1.outY;
    add2.xQ <== R[0];
    add2.yQ <== R[1];    

    //prepare to create the Schnorr challenge c = H(R,X,m) using SHA256
    component hash = Sha256(bitLength*3);
    
    //write the x coordinate of R' into the hash input
    component Rbits = Num2Bits(bitLength);    
    add2.outX ==> Rbits.in;
    for  (var i=0; i<bitLength; i++) {
        Rbits.out[i] ==> hash.in[i];
    }
    //Write the public key X's x-coordinate into the hash input
    component Xsgbits = Num2Bits(bitLength);    
    X[0] ==> Xsgbits.in;
    for  (var i=0; i<bitLength; i++) {
        Xsgbits.out[i] ==> hash.in[bitLength+i];
    }

    //write the message m into the hash input
    component msgbits = Num2Bits(bitLength);    
    msg ==> msgbits.in;
    for  (var i=0; i<bitLength; i++) {
        msgbits.out[i] ==> hash.in[(bitLength*2)+i];
    } 

    component shaOutputAsNumber = Bits2Num(bitLength);   
     for  (var i=0; i<bitLength; i++) {
        hash.out[i] ==> shaOutputAsNumber.in[i];
    } 

    log("final Schnorr check");
    component addModq = add_mod_q(64,4); 
    addModq.a <== shaOutputAsNumber.out;
    addModq.b <== beta;
    log(shaOutputAsNumber.out+ beta);
    log(addModq.c);
    c ===  addModq.c; 

}


template SplitIntoChunks(bits,chuncks) {
    signal input in;
    signal output out[chuncks];


    out[0] <-- in % (1 << bits);
    var a = (in \ (1 << bits)) ;
    for (var i = 1; i < chuncks; i++) {
        out[i] <-- a % (1 << bits);
        a = (a \ (1 << bits)) ;
    }  
    var sum  = out[0] ;
    for (var i = 1; i < chuncks; i++) {
        sum = sum+  out[i]* (1 << (bits*i));
    }  
    in === sum;
}

//this function requires an arithmetization field >q. Dont
//use with standart CIRCOM. 
template add_mod_q(n,k) {
    //apparently n=64 k=4 gives the best results
    signal input a;
    signal input b;
    signal output c;
    component splittA = SplitIntoChunks(n,k);
    splittA.in <== a;
    
    component splittB = SplitIntoChunks(n,k);
    splittB.in <== b;
    
    component qChuncks = SplitIntoChunks(n,k);
    qChuncks.in <== 115792089237316195423570985008687907852837564279074904382605163141518161494337;
    //perform addition mod q
    //TODO mod reduce.. 
    component big_add = BigAddModP(n, k);
    for (var i = 0; i < k; i++) {
        big_add.a[i] <== splittA.out[i];
        big_add.b[i] <== splittB.out[i];
        big_add.p[i] <== qChuncks.out[i];
        log(qChuncks.out[i]);
    }  

    var sum  = big_add.out[0] ;
    for (var i = 1; i < k; i++) {
        sum = sum+  big_add.out[i]* (1 << (n*i));
    }  
    //assert that statment cc ==  H(R,X,m) + beta mod p
    log(sum);
    c <==sum;

}


template BigLessThan(n, k){
    signal input a[k];
    signal input b[k];
    signal output out;

    component lt[k];
    component eq[k];
    for (var i = 0; i < k; i++) {
        lt[i] = LessThan(n);
        lt[i].in[0] <== a[i];
        lt[i].in[1] <== b[i];
        eq[i] = IsEqual();
        eq[i].in[0] <== a[i];
        eq[i].in[1] <== b[i];
    }

    // ors[i] holds (lt[k - 1] || (eq[k - 1] && lt[k - 2]) .. || (eq[k - 1] && .. && lt[i]))
    // ands[i] holds (eq[k - 1] && .. && lt[i])
    // eq_ands[i] holds (eq[k - 1] && .. && eq[i])
    component ors[k - 1];
    component ands[k - 1];
    component eq_ands[k - 1];
    for (var i = k - 2; i >= 0; i--) {
        ands[i] = AND();
        eq_ands[i] = AND();
        ors[i] = OR();

        if (i == k - 2) {
           ands[i].a <== eq[k - 1].out;
           ands[i].b <== lt[k - 2].out;
           eq_ands[i].a <== eq[k - 1].out;
           eq_ands[i].b <== eq[k - 2].out;
           ors[i].a <== lt[k - 1].out;
           ors[i].b <== ands[i].out;
        } else {
           ands[i].a <== eq_ands[i + 1].out;
           ands[i].b <== lt[i].out;
           eq_ands[i].a <== eq_ands[i + 1].out;
           eq_ands[i].b <== eq[i].out;
           ors[i].a <== ors[i + 1].out;
           ors[i].b <== ands[i].out;
        }
     }
     out <== ors[0].out;
}


//Selfmade. Dont trust. 
// calculates (a + b) % p 
template BigAddModP(n, k){
    signal input a[k];
    signal input b[k];
    signal input p[k];
    signal output out[k];

    component big_add = BigAdd(n, k);
    for (var i = 0; i < k; i++) {
        big_add.a[i] <== a[i];
        big_add.b[i] <== b[i];
    }

    //if q< a+b then return a+b - q
    component lt = BigLessThan(n,k+1);

    for (var i1 = 0; i1 < k; i1++) {
        lt.a[i1] <== p[i1];
        lt.b[i1] <== big_add.out[i1];
    }
    lt.a[k] <== 0;
    lt.b[k] <== big_add.out[k];

    //a+b - q
    component big_sub = BigSub(n, k);
    for (var i = 0; i < k; i++) {
        big_sub.a[i] <== big_add.out[i];
        big_sub.b[i] <== p[i];
    }
    
    for (var idx = 0; idx < k; idx++) {
        out[idx] <-- 1*(big_add.out[idx]*(1 - lt.out) +big_sub.out[idx]*lt.out);
    }  
}
// a[i], b[i] in 0... 2**n-1
// represent a = a[0] + a[1] * 2**n + .. + a[k - 1] * 2**(n * k)
template BigAdd(n, k) {
    assert(n <= 252);
    signal input a[k];
    signal input b[k];
    signal output out[k + 1];

    component unit0 = ModSum(n);
    unit0.a <== a[0];
    unit0.b <== b[0];
    out[0] <== unit0.sum;

    component unit[k - 1];
    for (var i = 1; i < k; i++) {
        unit[i - 1] = ModSumThree(n);
        unit[i - 1].a <== a[i];
        unit[i - 1].b <== b[i];
        if (i == 1) {
            unit[i - 1].c <== unit0.carry;
        } else {
            unit[i - 1].c <== unit[i - 2].carry;
        }
        out[i] <== unit[i - 1].sum;
    }
    out[k] <== unit[k - 2].carry;
}

// addition mod 2**n with carry bit
template ModSum(n) {
    assert(n <= 252);
    signal input a;
    signal input b;
    signal output sum;
    signal output carry;

    component n2b = Num2Bits(n + 1);
    n2b.in <== a + b;
    carry <== n2b.out[n];
    sum <== a + b - carry * (1 << n);
}

template ModSumThree(n) {
    assert(n + 2 <= 253);
    signal input a;
    signal input b;
    signal input c;
    signal output sum;
    signal output carry;

    component n2b = Num2Bits(n + 2);
    n2b.in <== a + b + c;
    carry <== n2b.out[n] + 2 * n2b.out[n + 1];
    sum <== a + b + c - carry * (1 << n);
}

// a[i], b[i] in 0... 2**n-1
// represent a = a[0] + a[1] * 2**n + .. + a[k - 1] * 2**(n * k)
// assume a >= b
template BigSub(n, k) {
    assert(n <= 252);
    signal input a[k];
    signal input b[k];
    signal output out[k];
    signal output underflow;

    component unit0 = ModSub(n);
    unit0.a <== a[0];
    unit0.b <== b[0];
    out[0] <== unit0.out;

    component unit[k - 1];
    for (var i = 1; i < k; i++) {
        unit[i - 1] = ModSubThree(n);
        unit[i - 1].a <== a[i];
        unit[i - 1].b <== b[i];
        if (i == 1) {
            unit[i - 1].c <== unit0.borrow;
        } else {
            unit[i - 1].c <== unit[i - 2].borrow;
        }
        out[i] <== unit[i - 1].out;
    }
    underflow <== unit[k - 2].borrow;
}
// a - b
template ModSub(n) {
    assert(n <= 252);
    signal input a;
    signal input b;
    signal output out;
    signal output borrow;
    component lt = LessThan(n);
    lt.in[0] <== a;
    lt.in[1] <== b;
    borrow <== lt.out;
    out <== borrow * (1 << n) + a - b;
}

// a - b - c
// assume a - b - c + 2**n >= 0
template ModSubThree(n) {
    assert(n + 2 <= 253);
    signal input a;
    signal input b;
    signal input c;
    assert(a - b - c + (1 << n) >= 0);
    signal output out;
    signal output borrow;
    signal b_plus_c;
    b_plus_c <== b + c;
    component lt = LessThan(n + 1);
    lt.in[0] <== a;
    lt.in[1] <== b_plus_c;
    borrow <== lt.out;
    out <== borrow * (1 << n) + a - b_plus_c;
}

component main {public [X,R,c,C0,Cmsg,pred,ek]}= Main(8);
