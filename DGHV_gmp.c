#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>

#include <gmp.h> //compiler avec le lien de librairie -lgmp

//https://asecuritysite.com/encryption/hom_public implementation deja faite + interface pour expliquer
//https://theses.hal.science/tel-01772355/document page 35 explication de l'algo -> source sur
//https://www.utc.fr/~wschon/sr06/tx_chiffrement_homomorphe/pages/dghv.html -> algo expliquer

//boostrapping explication + algo : https://www.utc.fr/~wschon/sr06/tx_chiffrement_homomorphe/pages/bootstrapping.html

/*         Variable Global              */
#define SIZE 4
gmp_randstate_t state;
// Parametre du probleme :
int etha = 49;    // taille cle privée
int tau = 5;       // nb de xi dans la clé publique
int gam = 50;     // la taille de q
int rho = 2;        // la taille du bruit

/*              Utils                   */
mpz_t* init_tab(int size){
    mpz_t* bin = (mpz_t*)malloc(size*sizeof(mpz_t));
    for(int i = 0; i < size; i++){
        mpz_init(bin[i]);
        mpz_set_ui(bin[i], 0);
    }
    return bin;
}

void clear_tab(mpz_t* tab, int size){
    for(int i = 0; i < size; i++){
        mpz_clear(tab[i]);
    }
    free(tab);
}

void print_tab(mpz_t* array, int size){
    for(int i = 0; i < size; i++){
        gmp_printf("%Zd ", array[i]);
    }printf("\n");
}

/*              Struct                   */
mpz_t* to_bin(mpz_t message){
    mpz_t mes;
    mpz_init_set(mes, message); //copy de message pour ne pas l'ecraser

    mpz_t* bin;
    bin = init_tab(SIZE);

    mpz_t expo_max;
    mpz_init(expo_max);
    mpz_ui_pow_ui(expo_max, 2, SIZE - 1);
    for(int i = 0; i < SIZE; i++){
        if(mpz_cmp(mes, expo_max) >= 0){
            mpz_set_ui(bin[i], 1);
            mpz_sub(mes, mes, expo_max);
        }
        else{
            mpz_set_ui(bin[i], 0);
        }
        mpz_divexact_ui(expo_max, expo_max, 2);
    }
    mpz_clear(expo_max);
    return bin;
}

void to_message(mpz_ptr rop, mpz_t* bin){
    mpz_t mes;
    mpz_init_set_ui(mes, 0);
    for(int i = 0; i < SIZE; i++){
        if(mpz_cmp_ui(bin[i], 1) == 0){
            mpz_t tmp;
            mpz_init(tmp);
            mpz_ui_pow_ui(tmp, 2, SIZE - 1 - i);
            mpz_add(mes, mes, tmp);
            mpz_clear(tmp);
        }
    }
    mpz_set(rop, mes);
    return;
}

/*              DGHV                   */
void cle_secrete(mpz_ptr p){
    mpz_urandomb(p, state, etha);
    while(mpz_probab_prime_p(p, 35) == 0){ mpz_urandomb(p, state, etha); }
    return;
}

mpz_t* cle_publique(mpz_t p){
    mpz_t* public_key;
    public_key = init_tab(tau);

    for(int i = 0; i < tau; i++){
        mpz_t r;
        mpz_init(r);
        mpz_urandomb(r, state, (unsigned long)rho);
        mpz_t q;
        mpz_init(q);
        mpz_urandomb(q, state, (unsigned long)gam);

	    //public_key[i] = (q * p) + (2 * r);
        mpz_t mul1, mul2;
        mpz_init(mul1);
        mpz_init(mul2);
        mpz_mul(mul1, q, p);
        mpz_mul_ui(mul2, r, 2);
        mpz_add(public_key[i], mul1, mul2);

        mpz_clear(r);
        mpz_clear(q);
        mpz_clear(mul1);
        mpz_clear(mul2);
    }
    return public_key;
}

void enc(mpz_t* bits, mpz_t* cipher, mpz_t* public_key){
    for(int i = 0; i < SIZE; i++){
        mpz_t sum;
        mpz_init_set_ui(sum, 0);
        for(int j = 0; j < tau; j++){
            mpz_t alea;
            mpz_init(alea);
            mpz_urandomb(alea, state, 1);
            if(mpz_cmp_ui(alea, 1) == 0){
                mpz_add(sum, sum, public_key[j]);
            }
            mpz_clear(alea);
        }
	    mpz_t r;
        mpz_init(r);
        mpz_urandomb(r, state, rho);

        //cipher[i] = sum + (2*r) + bits[i];
        mpz_mul_ui(r,r,2);
	    mpz_add(sum, sum, r);
        mpz_add(cipher[i], sum, bits[i]);
        mpz_clear(r);

        mpz_clear(sum);
    }
    return;
}

void enc_mpz(mpz_t clair, mpz_t cipher, mpz_t* public_key){
    mpz_t sum;
    mpz_init_set_ui(sum, 0);
    for(int j = 0; j < tau; j++){
        mpz_t alea;
        mpz_init(alea);
        mpz_urandomb(alea, state, 1);
        if(mpz_cmp_ui(alea, 1) == 0){
            mpz_add(sum, sum, public_key[j]);
        }
        mpz_clear(alea);
    }
	mpz_t r;
    mpz_init(r);
    mpz_urandomb(r, state, rho);

    //cipher = sum + (2*r) + clair;
    mpz_mul_ui(r,r,2);
	mpz_add(sum, sum, r);
    mpz_add(cipher, sum, clair);
    mpz_clear(r);

    mpz_clear(sum);
    return;
}

void dec(mpz_t* decipher, mpz_t* cipher, int size, mpz_t p){
    for(int i = 0; i < size; i++){
        //decipher[i] = (cipher[i] % p) % 2;
        mpz_mod(decipher[i], cipher[i], p);
        mpz_mod_ui(decipher[i], decipher[i], 2);
    }
    return;
}

mpz_t* sum_reelle(mpz_t* a, mpz_t* b){
    mpz_t* c;
    c = init_tab(SIZE);
    mpz_add(c[SIZE - 1], a[SIZE - 1], b[SIZE - 1]);

    mpz_t carry;
    mpz_init(carry);
    mpz_mul(carry, a[SIZE - 1], b[SIZE - 1]);

    mpz_t carry2;
    mpz_init(carry2);

    for(int i = SIZE - 2; i >= 0; i--){
        //carry2 = ((a[i] ^ b[i]) & carry) ^ (a[i] & b[i]);
        mpz_t tmp1; mpz_init(tmp1);
        mpz_add(tmp1, a[i], b[i]);
        mpz_mul(tmp1, tmp1, carry);
        mpz_t tmp2; mpz_init(tmp2);
        mpz_mul(tmp2, a[i], b[i]);
        mpz_add(carry2, tmp1, tmp2);
        mpz_clear(tmp1); mpz_clear(tmp2);

        //c[i] = (a[i] ^ b[i]) ^ carry;
        mpz_add(c[i], a[i], b[i]);
        mpz_add(c[i], c[i], carry);
                     
        mpz_set(carry,carry2);
    }

    mpz_clear(carry);
    mpz_clear(carry2);

    return c;
}

void bootstrapping(mpz_t* new_cipher, mpz_t* cipher, int size, mpz_t s, mpz_t* public_key){
    //Dec(chiffre(cle_secrete) = s, chiffré(chiffre)) = chiffre (Dec(cle_secrete, c)) = chiffre(m)
    mpz_t* c_cipher = init_tab(size);
    enc(cipher, c_cipher, public_key);

    for(int i = 0; i < size; i++){
        mpz_mod(new_cipher[i], c_cipher[i], s);
    }

    clear_tab(c_cipher, size);
}

void bootstrapping_bin(mpz_t* new_cipher, mpz_t* cipher, int size, mpz_t s){
    //Dec(chiffré(cle_secrete) = s, chiffré(chiffre)) = chiffré (Dec(cle_secrete, c)) = chiffré(m)
    dec(new_cipher, cipher, size, s);
}

/*              Test                   */
void affichage_bin_int(char* argv[]){
    mpz_t a;
    mpz_init_set_str(a, argv[1], 10);
    gmp_printf("a = %Zd\n", a);
    
    mpz_t* a_bin = to_bin(a);
    print_tab(a_bin, SIZE);

    mpz_t mes;
    mpz_init(mes);
    to_message(mes, a_bin);

    mpz_clear(a);
    clear_tab(a_bin, SIZE);
    mpz_clear(mes);
}

void affichage_enc_dec(char* message){
    //message
    mpz_t m;
    mpz_init_set_str(m, message, 10);
    gmp_printf("message a coder est : %Zd\n", m);
    mpz_t* m_bin = to_bin(m);
    printf("messsage bits : "); print_tab(m_bin, SIZE);

    //cle secrete
    mpz_t p;
    mpz_init(p);
    cle_secrete(p);
    gmp_printf("cle_secrete = %Zd\n", p);    

    //cle publique
    mpz_t* public_key;
    public_key = cle_publique(p);
    printf("Public key : "); print_tab(public_key, tau);

    //chiffrement
    mpz_t* cipher = init_tab(SIZE);
    enc(m_bin, cipher, public_key);
    printf("Cipher bits : "); print_tab(cipher, SIZE);

    //dechiffrement
    mpz_t* decipher = init_tab(SIZE);
    dec(decipher, cipher, SIZE, p);
    printf("Decipher bits : "); print_tab(decipher, SIZE);
    mpz_t m_dec;
    mpz_init(m_dec);
    to_message(m_dec, decipher);
    gmp_printf("decipher message : %Zd\n", m_dec);

    //free
    mpz_clear(m);
    clear_tab(m_bin, SIZE);
    mpz_clear(p);
    clear_tab(public_key, tau);
    clear_tab(cipher, SIZE);
    clear_tab(decipher, SIZE);
    mpz_clear(m_dec);
}

void affiche_sum(char* message1, char* message2){
    //mesurer le termps d'exécution
    time_t begin = time(NULL);

    //cle secrete
    mpz_t p;
    mpz_init(p);
    cle_secrete(p);
    gmp_printf("cle_secrete = %Zd\n", p);

    time_t t1 = time(NULL);

    //cle publique
    mpz_t* public_key;
    public_key = cle_publique(p);
    printf("Public key : "); print_tab(public_key, tau);

    time_t t2 = time(NULL);

    //message
    mpz_t a;
    mpz_init_set_str(a, message1, 10);
    gmp_printf("a = %Zd\n", a);
    mpz_t* a_bin = to_bin(a);
    print_tab(a_bin, SIZE);

    mpz_t* a_cipher = init_tab(SIZE);
    enc(a_bin, a_cipher, public_key);
    printf("Cipher bits a : "); print_tab(a_cipher, SIZE);

    mpz_t b;
    mpz_init_set_str(b, message2, 10);
    gmp_printf("b = %Zd\n", b);
    mpz_t* b_bin = to_bin(b);
    print_tab(b_bin, SIZE);

    mpz_t* b_cipher = init_tab(SIZE);
    enc(b_bin, b_cipher, public_key);
    printf("Cipher bits b : "); print_tab(b_cipher, SIZE);

    mpz_t* c_bin;
    c_bin = sum_reelle(a_cipher, b_cipher); //la somme marche avec a_bin et b_bin (mais ce n'est pas les chiffrer)
    printf("c sum : "); print_tab(c_bin, SIZE);

    mpz_t* c_decipher = init_tab(SIZE);
    dec(c_decipher, c_bin, SIZE, p);
    printf("Decipher bits : "); print_tab(c_decipher, SIZE);

    mpz_t c;
    mpz_init(c);
    to_message(c, c_decipher);
    gmp_printf("somme = %Zd\n", c);

    mpz_t sum_correct; mpz_init(sum_correct); mpz_add(sum_correct, a, b);
    gmp_printf("résultat attendu : %Zd + %Zd = %Zd\n", a, b, sum_correct);
    mpz_clear(sum_correct);

    mpz_clear(a);
    clear_tab(a_bin, SIZE);
    mpz_clear(b);
    clear_tab(b_bin, SIZE);
    mpz_clear(c);
    clear_tab(c_bin, SIZE);
    mpz_clear(p);
    clear_tab(public_key, tau);
    clear_tab(a_cipher, SIZE);
    clear_tab(b_cipher, SIZE);
    clear_tab(c_decipher, SIZE);

    time_t end = time(NULL);
    unsigned long secrete = (unsigned long) difftime( t1, begin );
    printf( "temps calcul cle secrete : %ld sec\n", secrete );
    unsigned long public = (unsigned long) difftime( t2, t1 );
    printf( "temps calcul cle public : %ld sec\n", public );
    unsigned long total = (unsigned long) difftime( end, begin );
    printf( "temps total : %ld sec\n", total );
}

void affiche_2sum(char* message1, char* message2){
    //mesurer le termps d'exécution
    time_t begin = time(NULL);

    //cle secrete
    mpz_t p;
    mpz_init(p);
    cle_secrete(p);
    gmp_printf("cle_secrete = %Zd\n", p);

    time_t t1 = time(NULL);

    //cle publique
    mpz_t* public_key;
    public_key = cle_publique(p);
    printf("Public key : "); print_tab(public_key, tau);

    time_t t2 = time(NULL);

    //message
    mpz_t a;
    mpz_init_set_str(a, message1, 10);
    gmp_printf("a = %Zd\n", a);
    mpz_t* a_bin = to_bin(a);
    print_tab(a_bin, SIZE);

    mpz_t* a_cipher = init_tab(SIZE);
    enc(a_bin, a_cipher, public_key);
    printf("Cipher bits a : "); print_tab(a_cipher, SIZE);

    mpz_t b;
    mpz_init_set_str(b, message2, 10);
    gmp_printf("b = %Zd\n", b);
    mpz_t* b_bin = to_bin(b);
    print_tab(b_bin, SIZE);

    mpz_t* b_cipher = init_tab(SIZE);
    enc(b_bin, b_cipher, public_key);
    printf("Cipher bits b : "); print_tab(b_cipher, SIZE);

    mpz_t* c_bin;
    c_bin = sum_reelle(a_cipher, b_cipher); //la somme marche avec a_bin et b_bin (mais ce n'est pas les chiffrer)
    printf("c sum : "); print_tab(c_bin, SIZE);

    //bootstrap
    mpz_t s; //cle secrete chiffre par pk
    mpz_init(s);
    enc_mpz(p, s, public_key);
    bootstrapping(c_bin, c_bin, SIZE, s, public_key);
    printf("c bootstrap : "); print_tab(c_bin, SIZE);

    //2e sum
    c_bin = sum_reelle(c_bin, b_cipher);
    printf("c sum sum : "); print_tab(c_bin, SIZE);

    mpz_t* c_decipher = init_tab(SIZE);
    dec(c_decipher, c_bin, SIZE, p);
    printf("Decipher bits : "); print_tab(c_decipher, SIZE);

    mpz_t c;
    mpz_init(c);
    to_message(c, c_decipher);
    gmp_printf("somme = %Zd\n", c);

    mpz_t sum_correct; mpz_init(sum_correct); mpz_add(sum_correct, a, b); mpz_add(sum_correct, sum_correct, b);
    gmp_printf("résultat attendu : %Zd + %Zd + %Zd = %Zd\n", a, b, b, sum_correct);
    mpz_clear(sum_correct);

    mpz_clear(a);
    clear_tab(a_bin, SIZE);
    mpz_clear(b);
    clear_tab(b_bin, SIZE);
    mpz_clear(c);
    clear_tab(c_bin, SIZE);
    mpz_clear(p);
    clear_tab(public_key, tau);
    clear_tab(a_cipher, SIZE);
    clear_tab(b_cipher, SIZE);
    clear_tab(c_decipher, SIZE);

    time_t end = time(NULL);
    unsigned long secrete = (unsigned long) difftime( t1, begin );
    printf( "temps calcul cle secrete : %ld sec\n", secrete );
    unsigned long public = (unsigned long) difftime( t2, t1 );
    printf( "temps calcul cle public : %ld sec\n", public );
    unsigned long total = (unsigned long) difftime( end, begin );
    printf( "temps total : %ld sec\n", total );
}

void affiche_test_boostrap_0(){
    //mesurer le termps d'exécution
    time_t begin = time(NULL);

    //cle secrete
    mpz_t p;
    mpz_init(p);
    cle_secrete(p);
    gmp_printf("cle_secrete = %Zd\n", p);

    time_t t1 = time(NULL);

    //cle publique
    mpz_t* public_key;
    public_key = cle_publique(p);
    printf("Public key : "); print_tab(public_key, tau);

    time_t t2 = time(NULL);

    //message
    mpz_t a;
    mpz_init_set_str(a, "0", 10);
    gmp_printf("a = %Zd\n", a);
    mpz_t* a_bin = to_bin(a);
    print_tab(a_bin, 1);

    mpz_t* a_cipher = init_tab(1);
    enc(a_bin, a_cipher, public_key);
    printf("Cipher bits a : "); print_tab(a_cipher, 1);

    mpz_t b;
    mpz_init_set_str(b, "0", 10);
    gmp_printf("b = %Zd\n", b);
    mpz_t* b_bin = to_bin(b);
    print_tab(b_bin, 1);

    mpz_t* b_cipher = init_tab(1);
    enc(b_bin, b_cipher, public_key);
    printf("Cipher bits b : "); print_tab(b_cipher, 1);

    //sum 1
    mpz_t* sum1_bin;
    sum1_bin = sum_reelle(a_cipher, b_cipher); //la somme marche avec a_bin et b_bin (mais ce n'est pas les chiffrer)
    printf("sum1 sum : "); print_tab(sum1_bin, 1);
    mpz_t* sum1_decipher = init_tab(1);
    dec(sum1_decipher, sum1_bin, 1, p);
    printf("sum1 bits : "); print_tab(sum1_decipher, 1);

    //bootstrap
    mpz_t s; //cle secrete chiffre par pk
    mpz_init(s);
    enc_mpz(p, s, public_key);
    gmp_printf("s = %Zd\n", s);
    mpz_t* sum1_bin_bootstrap;
    bootstrapping_bin(sum1_bin_bootstrap, sum1_bin, 1, s);
    printf("sum1 bootstrap : "); print_tab(sum1_bin, 1);
    mpz_t* sum1_bootstrap_decipher = init_tab(1);
    dec(sum1_bootstrap_decipher, sum1_bin_bootstrap, 1, p);
    printf("sum1 bootstrap decipher : "); print_tab(sum1_bootstrap_decipher, 1);

    
    //clear
    mpz_clear(a);
    clear_tab(a_bin, SIZE);
    mpz_clear(b);
    clear_tab(b_bin, SIZE);
    clear_tab(sum1_bin, SIZE);
    mpz_clear(p);
    clear_tab(public_key, tau);
    clear_tab(a_cipher, SIZE);
    clear_tab(b_cipher, SIZE);
    clear_tab(sum1_decipher, SIZE);

    time_t end = time(NULL);
    unsigned long secrete = (unsigned long) difftime( t1, begin );
    printf( "temps calcul cle secrete : %ld sec\n", secrete );
    unsigned long public = (unsigned long) difftime( t2, t1 );
    printf( "temps calcul cle public : %ld sec\n", public );
    unsigned long total = (unsigned long) difftime( end, begin );
    printf( "temps total : %ld sec\n", total );
}

void affiche_sum_0_n(int n){
    //mesurer le termps d'exécution
    time_t begin = time(NULL);

    //cle secrete
    mpz_t p;
    mpz_init(p);
    cle_secrete(p);
    gmp_printf("cle_secrete = %Zd\n", p);

    time_t t1 = time(NULL);

    //cle publique
    mpz_t* public_key;
    public_key = cle_publique(p);
    printf("Public key : "); print_tab(public_key, tau);

    time_t t2 = time(NULL);

    //message
    mpz_t a;
    mpz_init_set_str(a, "0", 10);
    gmp_printf("a = %Zd\n", a);
    mpz_t* a_bin = to_bin(a);
    printf("Bits clair a : "); print_tab(a_bin, SIZE);

    mpz_t* a_cipher = init_tab(SIZE);
    enc(a_bin, a_cipher, public_key);
    printf("Cipher bits a : "); print_tab(a_cipher, SIZE);

    mpz_t b;
    mpz_init_set_str(b, "0", 10);
    gmp_printf("b = %Zd\n", b);
    mpz_t* b_bin = to_bin(b);
    printf("Bits clair b : "); print_tab(b_bin, SIZE);

    mpz_t* b_cipher = init_tab(SIZE);
    enc(b_bin, b_cipher, public_key);
    printf("Cipher bits b : "); print_tab(b_cipher, SIZE);

    //faire les n somme de 0
    mpz_t* c_bin;
    c_bin = sum_reelle(a_cipher, b_cipher);
    printf("valeur initiale : "); print_tab(c_bin, SIZE);
    for(int i = 0; i < n; i++){
        c_bin = sum_reelle(a_cipher, b_cipher);
    }printf("valeur la meme mais refait n fois : "); print_tab(c_bin, SIZE);


    mpz_clear(a);
    clear_tab(a_bin, SIZE);
    mpz_clear(b);
    clear_tab(b_bin, SIZE);
    clear_tab(c_bin, SIZE);
    mpz_clear(p);
    clear_tab(public_key, tau);
    clear_tab(a_cipher, SIZE);
    clear_tab(b_cipher, SIZE);

    time_t end = time(NULL);
    double secrete = difftime( t1, begin );
    printf( "temps calcul cle secrete : %f sec\n", secrete );
    double public = difftime( t2, t1 );
    printf( "temps calcul cle public : %f sec\n", public );
    double total = difftime( end, begin );
    printf( "temps total : %f sec\n", total );
}

int main(int argc, char *argv[]){
    //initialisation de la graine de hasard 
    unsigned long seed = (unsigned long)time(NULL);
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, seed);
    
    //affiche_test_boostrap_0();

    int n = 52138334;
    // affiche_sum_0_n(n);
    // printf("%d\n",n);

    affiche_sum("1", "3");

    gmp_randclear(state);

    return 0;
}