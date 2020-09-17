#ifndef ENCRYPT_H
#define ENCRYPT_H

#include "xor.h"
#include "rc4.h"

enum socks_encrypt_method {
	NO_ENCRYPT = 0,
	XOR_METHOD = 1,
	RC4_METHOD = 2,
};

struct socks_encryptor {
	enum socks_encrypt_method enc_method;
	union {
		struct xor_encryptor xor_enc;
		struct rc4_encryptor rc4_enc;
	};
};

struct socks_encryptor *socks_create_encryptor(enum socks_encrypt_method method, const uint8_t *key, size_t key_len);

void socks_release_encryptor(struct socks_encryptor *encryptor);

uint8_t *socks_encrypt(struct socks_encryptor *encryptor, uint8_t *dest, uint8_t *src, size_t src_len);

uint8_t *socks_decrypt(struct socks_encryptor *decryptor, uint8_t *dest, uint8_t *src, size_t src_len);
#endif