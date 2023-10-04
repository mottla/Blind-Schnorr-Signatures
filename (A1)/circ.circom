
pragma circom 2.1.6;
include "../circomlib/circuits/babyjub.circom";
include "../circomlib/circuits/escalarmulfix.circom";
include "../circomlib/circuits/bitify.circom";
include "../circomlib/circuits/poseidon.circom";
include "../circomlib/circuits/gates.circom";

template Main() {    
    signal input R[2];
    signal input c;
    signal input Cmsg;  
    signal input C0[2];  
    signal input msg;
    signal input rho;
    var bits = 254; //the order r of the babyjub curve is 251 bits. 
    var i;
    var base[2] = [5299619240641551281634865583518297030282874472190772894086521144482721001553,
            16950150798460657717958625567821834550301663161624707787222815936182638968203];   
    var X[2] =  [5299619240641551281634865583518297030282874472190772894086521144482721001553,
            16950150798460657717958625567821834550301663161624707787222815936182638968203];   
    var ek[2] = [5299619240641551281634865583518297030282874472190772894086521144482721001553,
            16950150798460657717958625567821834550301663161624707787222815936182638968203];   
    //ElGamal Enc
    
    log("start");
    component n2b_rho= Num2Bits(251);  //a field element has 254 bit, but we only care about the 251 first bits. Revisit this point and rethink
    rho ==> n2b_rho.in;
    
    // X^rho
    component ek_rho = EscalarMulFix(251,ek);    
    for  (i=0; i < 251; i++) {
        n2b_rho.out[i] ==> ek_rho.e[i];
    }
    // C_0 == g^rho
    component g_pow_rho = EscalarMulFix(251,base);    
    for  (i=0; i < 251; i++) {
        n2b_rho.out[i] ==> g_pow_rho.e[i];
    }
    log("comparing C0");
    log(g_pow_rho.out[0]);
    log(g_pow_rho.out[1]);
    C0[0] ===  g_pow_rho.out[0];
    C0[1] ===  g_pow_rho.out[1];


    log("start hash");
     // H(X^rho) 
    //hash alpha and beta group elements to obtain uniform blinding factors
    component pEx = PoseidonEx(2, 3);
    pEx.initialState <== 0;  //Why setting it to 0.. need to read the paper
    pEx.inputs[0] <== ek_rho.out[0];
    pEx.inputs[1] <== ek_rho.out[1];
    

    log("hashed alpha");
    log(pEx.out[0]);
    log("hashed beta");
    log(pEx.out[1]);
    var beta = pEx.out[1];
    log("hashed message blinding");
    log(pEx.out[2]);    
    log("assert encryption of message is equal to the provided ciphertext");   
    log(msg+pEx.out[2]);
     // H(ek^rho) + msg == c1
    Cmsg === msg+pEx.out[2]; 
 

     //compute alpha*G
    component n2b_alpha = Num2Bits(bits);
    component alpha_G = EscalarMulFix(bits,base);
  
    pEx.out[0] ==> n2b_alpha.in;
    for  (i=0; i<bits; i++) {
        n2b_alpha.out[i] ==> alpha_G.e[i];
    }

    //compute beta*X
    component n2b_beta = Num2Bits(bits);
    component beta_X = EscalarMulFix(bits,X);
    
    pEx.out[1] ==> n2b_beta.in;
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
    

    component hash = Poseidon(3);
    hash.inputs[0] <== add2.xout;
    hash.inputs[1] <== X[0];
    hash.inputs[2] <== msg;

 log("final Schnorr check");
    component addModq = add_mod_q(64,4); 
    addModq.a <== hash.out;
    addModq.b <== beta;
    log(hash.out+ beta);
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

//return a+b mod q , where q is the order of the jubjubcurve
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
    qChuncks.in <== 2736030358979909402780800718157159386076813972158567259200215660948447373041;
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


component main {public [R,c,Cmsg,C0]}= Main();


