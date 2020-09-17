#ifndef XOR_H
#define XOR_H

#include <stdint.h>
#include <stdlib.h>

struct xor_encryptor {
    size_t encrypt_location;
    size_t decrypt_location;
    size_t key_len;
    uint8_t *key;
};

uint8_t *xor_encrypt(uint8_t *buf, size_t buf_len, const uint8_t *key, size_t key_len, size_t *location);
uint8_t *xor_decrypt(uint8_t *buf, size_t buf_len, const uint8_t *key, size_t key_len, size_t *location);
#endif