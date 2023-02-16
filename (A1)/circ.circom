
pragma circom 2.0.0;
include "../circomlib/circuits/babyjub.circom";
include "../circomlib/circuits/escalarmulany.circom";
include "../circomlib/circuits/escalarmulfix.circom";
include "../circomlib/circuits/bitify.circom";
include "../circomlib/circuits/poseidon.circom";

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
    log(hash.out+ pEx.out[1]);
    c ===  hash.out + pEx.out[1]; 
    

}

component main {public [R,c,Cmsg,C0]}= Main();



