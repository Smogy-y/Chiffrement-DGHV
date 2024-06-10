#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>

//https://asecuritysite.com/encryption/hom_public

void print_int64_array(int64_t* array, int64_t size){
    for(int64_t i = 0; i < size; i++){
        printf("%ld ", array[i]);
    }printf("\n");
}

int64_t expo_fast(int64_t x, int64_t n){
    if(n == 0){ return 1; }
    else{
        int64_t tps = expo_fast(x,n/2);
        if(n%2 == 0){ return tps * tps; }
        else{ return tps * tps * x; }
    }
}

typedef struct{
    int64_t* m;
    int64_t size;
} m_bin; //structure qui permet de stocke un message sous forme binaire, m est un tableau de 0 et 1, qui represente les bits du message stocke.

void free_bin(m_bin* bin){
    free(bin->m);
    free(bin);
}

m_bin* to_bin(int64_t mes){
    int64_t size = 0;
    int64_t num = mes;
    while(num > 1){
        size ++;
        num /= 2; 
    }
    m_bin* bin = (m_bin*)malloc(sizeof(m_bin));
    bin->size = size+1;
    bin->m = (int64_t*)malloc(bin->size*sizeof(int64_t));
    num = mes;
    for(int64_t i = 0; i < bin->size; i++){
        bin->m[bin->size - i - 1] = num % 2;
        num /= 2;
    }
    return bin;
}

int64_t to_message(m_bin* bin){
    int64_t mes = 0;
    for(int64_t i = 0; i < bin->size; i++){
        if(bin->m[i] == 1){
            mes += expo_fast(2, bin->size - 1 - i);
        }
    }
    return mes;
}

int main(int argc, char *argv[]){
    srand(time(NULL));

    int64_t m = (int64_t)atoi(argv[1]);
    printf("le massage a coder est : %ld\n", m);
    m_bin* bits = to_bin(m);
    int64_t p = (((rand() % 1000000) + 1000000)*2) + 1;
    
    printf("m: %ld\n", m);
    print_int64_array(bits->m, bits->size);
    printf("cle secrete : %ld\n", p);



    int64_t pk_size = 5;
    int64_t* public_key = (int64_t*)malloc(pk_size*sizeof(int64_t));
    
    printf("Public key : ");
    for(int64_t i = 0; i < pk_size; i++){
	    int64_t r = (rand() % 10) + 1;
	    int64_t q = (rand() % 10000) + 50000;
	    public_key[i] = (int64_t) (q * p) + (2 * r); 
    } print_int64_array(public_key, pk_size);


    int64_t* cipher = (int64_t*)malloc(bits->size*sizeof(int64_t));
    printf("Cipher bits : ");
    for(int64_t i = 0; i < bits->size; i++){
	    int64_t j1 = rand() % (pk_size - 1);
        int64_t j2 = rand() % (pk_size - 1);
        int64_t j3 = rand() % (pk_size - 1);
	    int64_t sum = public_key[j1] + public_key[j2] + public_key[j3];
	    int64_t r = (rand() % 10) + 1;
	    cipher[i] = (int64_t) sum + (2*r) + bits->m[i];
    } print_int64_array(cipher, bits->size);


    printf("Decipher bits : ");
    for(int64_t i = 0; i < bits->size; i++){;
	    printf("%ld ", (int64_t) (cipher[i] % p) %2);
    }printf("\n");
    printf("decipher message : %ld\n", to_message(bits));


    free(public_key);
    free(cipher);
    free_bin(bits);

    return 0;
}