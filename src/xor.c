#include "xor.h"

uint8_t *xor_encrypt(uint8_t *buf, size_t buf_len, const uint8_t *key, size_t key_len, size_t *location) {
    size_t i;
    
    for (i = 0; i < buf_len; i += 1) {
        buf[i] ^= key[(i + *location) % key_len];
    }
    *location = (buf_len + *location) % key_len; 
    return buf;
}

uint8_t *xor_decrypt(uint8_t *buf, size_t buf_len, const uint8_t *key, size_t key_len, size_t *location) {
    return xor_encrypt(buf, buf_len, key, key_len, location);
}