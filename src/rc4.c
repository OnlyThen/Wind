#include "rc4.h"

static void swap_bytes(uint8_t *a, uint8_t *b) {
	uint8_t temp;
	temp = *a;
	*a = *b;
	*b = temp;
}

void rc4_init(struct rc4_state *state, const uint8_t *key, size_t key_len) {
    size_t i;
    size_t j = 0;
    for (i = 0; i < 256; i += 1){
        state->perm[i] = (uint8_t)i;
    }
    state->index1 = 0;
    state->index2 = 0;
    for (i = 0; i < 256; i += 1) {
        j += state->perm[i] + key[i % key_len];
        swap_bytes(&state->perm[i], &state->perm[j]);
    }
}

void rc4_encrypt(struct rc4_state *state, const uint8_t *buf_in, uint8_t *buf_out, size_t buf_len) {
    size_t i;
    size_t j;
    for (i = 0; i < buf_len; i += 1) {
        state->index1 += 1;
        state->index2 += state->perm[state->index1];
        swap_bytes(&state->perm[state->index1], &state->perm[state->index2]);
        j = state->perm[state->index1] + state->perm[state->index2];
        buf_out[i] = buf_in[i] ^ state->perm[j];
    }  
}

void rc4_decrypt(struct rc4_state *state, const uint8_t *buf_in, uint8_t *buf_out, size_t buf_len) {
    rc4_encrypt(state, buf_in, buf_out, buf_len);
}