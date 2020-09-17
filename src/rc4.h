#ifndef RC4_H
#define RC4_H
#include <stdint.h>
#include <stdlib.h>

struct rc4_state {
    uint8_t perm[256];
    uint8_t index1;
    uint8_t index2;    
};

struct rc4_encryptor {
	struct rc4_state en_state;
	struct rc4_state de_state;
	size_t key_len;
	uint8_t *key;
};

void rc4_init(struct rc4_state *state, const uint8_t *key, size_t key_len);
void rc4_encrypt(struct rc4_state *state, const uint8_t *buf_in, uint8_t *buf_out, size_t buf_len);
void rc4_decrypt(struct rc4_state *state, const uint8_t *buf_in, uint8_t *buf_out, size_t buf_len);
#endif