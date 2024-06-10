#include <stdio.h>
#include <stdlib.h>

int main(){
    int n = 100000000;
    int c = 0;
    printf("debut");
    for(int i = 0; i < n; i++){
        c = c + i;
    }
    printf("%d\n", c);
    printf("fin\n");

    return 0;
}