
pragma circom 2.0.0;
include "../circomlib/circuits/babyjub.circom";
include "../circomlib/circuits/escalarmulany.circom";
include "../circomlib/circuits/bitify.circom";
include "../circomlib/circuits/sha256/sha256.circom";

template Main() {
    signal input X[2];
    signal input R[2];
    signal input c;
    signal input Cmsg[2];
    signal input Calpha[2];
    signal input Cbeta[2];
    signal input ek[2];
    signal input msg[2];
    signal input alpha[2];
    signal input beta[2];
    signal input rho[3];

    var base[2] = [5299619240641551281634865583518297030282874472190772894086521144482721001553,
            16950150798460657717958625567821834550301663161624707787222815936182638968203];

    //sanity check on messages
    log(1);
    log(alpha[0]);
    component chk_alpha = BabyCheck();
    chk_alpha.x <== alpha[0];
    chk_alpha.y <== alpha[1];
    log(2);
    component chk_beta= BabyCheck();
    chk_beta.x <== beta[0];
    chk_beta.y <== beta[1];
    component chk_msg = BabyCheck();
    chk_msg.x <== msg[0];
    chk_msg.y <== msg[1];

    //compute alpha*G
    component n2b_alpha = Num2Bits(254);
    component alpha_G = EscalarMulAny(254);
    alpha_G.p[0] <== base[0];
    alpha_G.p[1] <== base[1];
    var i;
    alpha[0] ==> n2b_alpha.in;
    for  (i=0; i<254; i++) {
        n2b_alpha.out[i] ==> alpha_G.e[i];
    }

    //compute beta*X
    component n2b_beta = Num2Bits(254);
    component beta_X = EscalarMulAny(254);
    beta_X.p[0] <== X[0];
    beta_X.p[1] <== X[1];
    
    beta[0] ==> n2b_beta.in;
    for  (i=0; i<254; i++) {
        n2b_beta.out[i] ==> beta_X.e[i];
    }

    // R' = R +aG+bX
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

    //ElGamal Enc
    // h^rho1 * msg == c1
    component n2b_rho1= Num2Bits(254);
    component ek_rho1 = EscalarMulAny(254);
    ek_rho1.p[0] <== ek[0];
    ek_rho1.p[1] <== ek[1];
    
    rho[0] ==> n2b_rho1.in;
    for  (i=0; i<254; i++) {
        n2b_rho1.out[i] ==> ek_rho1.e[i];
    }
    
    component add3 = BabyAdd();
    add3.x1 <== ek_rho1.out[0];
    add3.y1 <== ek_rho1.out[1];
    add3.x2 <== msg[0];
    add3.y2 <== msg[1];
    log(3); 
    log(add3.xout);
    log(add3.yout);
    Cmsg[0] === add3.xout;
    Cmsg[1] === add3.yout; 

        //ElGamal Enc
    // h^rho2 * alpha == c2
    component n2b_rho2= Num2Bits(254);
    component ek_rho2 = EscalarMulAny(254);
    ek_rho2.p[0] <== ek[0];
    ek_rho2.p[1] <== ek[1];
    
    rho[1] ==> n2b_rho2.in;
    for  (i=0; i<254; i++) {
        n2b_rho2.out[i] ==> ek_rho2.e[i];
    }
    
    component add4 = BabyAdd();
    add4.x1 <== ek_rho2.out[0];
    add4.y1 <== ek_rho2.out[1];
    add4.x2 <== alpha[0];
    add4.y2 <== alpha[1];
    log(4); 
    log(add4.xout);
    log(add4.yout);
    Calpha[0] === add4.xout;
    Calpha[1] === add4.yout; 

            //ElGamal Enc
    // h^rho3 * beta == c3
    component n2b_rho3= Num2Bits(254);
    component ek_rho3 = EscalarMulAny(254);
    ek_rho3.p[0] <== ek[0];
    ek_rho3.p[1] <== ek[1];
    
    rho[2] ==> n2b_rho3.in;
    for  (i=0; i<254; i++) {
        n2b_rho3.out[i] ==> ek_rho3.e[i];
    }
    
    component add5 = BabyAdd();
    add5.x1 <== ek_rho3.out[0];
    add5.y1 <== ek_rho3.out[1];
    add5.x2 <== beta[0];
    add5.y2 <== beta[1];
    log(5); 
    log(add5.xout);
    log(add5.yout);
    Cbeta[0] === add5.xout;
    Cbeta[1] === add5.yout; 

    component hash = Sha256(254*3);

    component rprime = Num2Bits(254);    
    add2.xout ==> rprime.in;

    component xbits = Num2Bits(254);    
    X[0] ==> xbits.in;
    component msgbits = Num2Bits(254);    
    msg[0] ==> msgbits.in;
    for  (i=0; i<254; i++) {
        rprime.out[i] ==> hash.in[i];
    }
    for  (i=0; i<254; i++) {
        xbits.out[i] ==> hash.in[254+i];
    }
    for  (i=0; i<254; i++) {
        msgbits.out[i] ==> hash.in[(254*2)+i];
    }

    component fin = Bits2Num(256);
    for  (i=0; i<256; i++) {
        hash.out[i] ==> fin.in[i];
    }
    log(fin.out+ beta[0]);
    c ===  fin.out + beta[0]; 
    

}

component main {public [X,R,c,Cmsg,Calpha,Cbeta]}= Main();
