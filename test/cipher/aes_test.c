#include "aes.h"
#include <stdlib.h> 
#include <stdio.h>

int main(int argc, char *argv[]) {
    char str[] = "1234";
    aes_key ak = {0};
    ak.rd_key[59] = 0xecc02974;
    ak.rounds = 64;
    unsigned long result; 
    unsigned long value = 100;
    
    return 0;
}