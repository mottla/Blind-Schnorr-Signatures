
pragma circom 2.0.0;
include "../circomlib/circuits/babyjub.circom";
include "../circomlib/circuits/escalarmulany.circom";
include "../circomlib/circuits/escalarmulfix.circom";
include "../circomlib/circuits/bitify.circom";
include "../circomlib/circuits/poseidon.circom";

template Main(n,l) {
    signal input X[2];
    signal input R[2];
    signal input c;
    signal input Cmsg[n];
    signal input ek[2];
     signal input C0[2]; 
    signal input msgPublicn[l];
    signal input msg[n];
    signal input rho;
    var bits = 254; //the order r of the babyjub curve is 251 bits. 
    var i;
    var base[2] = [5299619240641551281634865583518297030282874472190772894086521144482721001553,
            16950150798460657717958625567821834550301663161624707787222815936182638968203];   

    //ElGamal Enc
    // H(h^rho1) + msg == c1
    component n2b_rho1= Num2Bits(251);  //a field element has 254 bit, but we only care about the 251 first bits. Revisit this point and rethink
    component ek_rho1 = EscalarMulAny(251);
    ek_rho1.p[0] <== ek[0];
    ek_rho1.p[1] <== ek[1];
    
    rho ==> n2b_rho1.in;
    for  (i=0; i < 251; i++) {
        n2b_rho1.out[i] ==> ek_rho1.e[i];
    }

     // C_0 == g^rho
    component g_pow_rho = EscalarMulFix(251,base);    
    for  (i=0; i < 251; i++) {
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
    pEx.inputs[1] <== ek_rho1.out[1];
    

    log("hashed alpha");
    log(pEx.out[0]);
    log("hashed beta");
    log(pEx.out[1]);  
    log("start encryption of message is equal to the provided ciphertext");   
    
    var rand[n+1];
    rand[0] = pEx.out[2];
    //this is a bit of a mess.. seems we cant squeeze the spong arbitrary many times so this served as a quick workaround. I use PoseidonEx(1,2) since its more efficient that 1-1 poseidon it seems..
    component randEnc[n] ;
    for(var i=1;i<n;i+=2){
        randEnc[i] = PoseidonEx(1, 2);
        randEnc[i].initialState <== 0;
        randEnc[i].inputs[0] <== rand[i-1]; 
        rand[i] = randEnc[i].out[0];
        rand[i+1] = randEnc[i].out[1];
        
    }
    for(var i=0;i<n;i++){
        log(msg[i]+rand[i]);
        Cmsg[i] === msg[i]+rand[i] ;
    }
    
 

     //compute alpha*G
    component n2b_alpha = Num2Bits(bits);
    component alpha_G = EscalarMulFix(bits,base);
  
    pEx.out[0] ==> n2b_alpha.in;
    for  (i=0; i<bits; i++) {
        n2b_alpha.out[i] ==> alpha_G.e[i];
    }

    //compute beta*X
    component n2b_beta = Num2Bits(bits);
    component beta_X = EscalarMulAny(bits);
    beta_X.p[0] <== X[0];
    beta_X.p[1] <== X[1];
    
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
    

    component hash = Poseidon(2+n+l);
    hash.inputs[0] <== add2.xout;
    hash.inputs[1] <== X[0];
    for(var i=2;i<l+2;i++){
        hash.inputs[i] <== msgPublicn[i-2];
    }
    for(var i=l+2;i<n+2+l;i++){
        hash.inputs[i] <== msg[i-2-l];
    }
    
    log("final Schnorr check");
    log(hash.out+ pEx.out[1]);
    c ===  hash.out + pEx.out[1]; 
    

}

component main {public [X,ek,R,c,Cmsg,C0]}= Main(8,0);



