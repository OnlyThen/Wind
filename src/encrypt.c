#include "encrypt.h"
#include <string.h>
struct socks_encryptor *socks_create_encryptor(enum socks_encrypt_method method, const uint8_t *key, size_t key_len) {
    struct socks_encryptor *encryptor;

    switch (method) {
    case XOR_METHOD:
        encryptor = calloc(1, sizeof(struct socks_encryptor));
        encryptor->enc_method = method;
        encryptor->xor_enc.key_len = key_len;
        encryptor->xor_enc.key = calloc(1, key_len);
        memcpy(encryptor->xor_enc.key, key, key_len);
		return encryptor;
    case RC4_METHOD:
		encryptor = calloc(1, sizeof(typeof(*encryptor)));
		encryptor->enc_method = method;
		encryptor->rc4_enc.key_len = key_len;
        encryptor->rc4_enc.key = calloc(1, key_len);
		memcpy(encryptor->rc4_enc.key, key, key_len);
		rc4_init(&encryptor->rc4_enc.en_state, key, key_len);
		rc4_init(&encryptor->rc4_enc.de_state, key, key_len);
		return encryptor;
    default:
        return NULL;
    }

}

void socks_release_encryptor(struct socks_encryptor *encryptor) {
    switch (encryptor->enc_method) {
    case XOR_METHOD:
        free(encryptor->xor_enc.key);
        free(encryptor);
    case RC4_METHOD:
		free(encryptor->rc4_enc.key);
        free(encryptor);
    default:
        break;
    }
}

uint8_t *socks_encrypt(struct socks_encryptor *encryptor, uint8_t *dest, uint8_t *src, size_t src_len) {
    switch (encryptor->enc_method) {
    case XOR_METHOD:
        if (dest == src) {
			return xor_encrypt(src, src_len,
					encryptor->xor_enc.key,
					encryptor->xor_enc.key_len,
					&encryptor->xor_enc.encrypt_location);
        }
		else {
			memcpy(dest, src, src_len);
			return xor_encrypt(dest, src_len,
					encryptor->xor_enc.key,
					encryptor->xor_enc.key_len,
					&encryptor->xor_enc.encrypt_location);
		}
		break;
    case RC4_METHOD:
		rc4_encrypt(&encryptor->rc4_enc.en_state, src, dest, src_len);
        return dest;
    default:
        return NULL;
    }
}

uint8_t *socks_decrypt(struct socks_encryptor *decryptor, uint8_t *dest, uint8_t *src, size_t src_len) {
    switch (decryptor->enc_method) {
	case XOR_METHOD:
		if (dest == src) {
			return xor_decrypt(src, src_len,
					decryptor->xor_enc.key,
					decryptor->xor_enc.key_len,
					&decryptor->xor_enc.decrypt_location);
        }
		else {
			memcpy(dest, src, src_len);
			return xor_decrypt(dest, src_len,
					decryptor->xor_enc.key,
					decryptor->xor_enc.key_len,
					&decryptor->xor_enc.decrypt_location);
		}
		break;
	case RC4_METHOD:
		rc4_decrypt(&decryptor->rc4_enc.de_state, src, dest, src_len);
		return dest;
	default:
		return NULL;
	}
}