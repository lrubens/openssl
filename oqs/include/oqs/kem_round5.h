#ifndef __OQS_KEM_ROUND5_H
#define __OQS_KEM_ROUND5_H

#include <oqs/oqs.h>

#ifdef OQS_ENABLE_KEM_round5_r5n1_1kem_0d
#define OQS_KEM_round5_r5n1_1kem_0d_length_public_key 5214
#define OQS_KEM_round5_r5n1_1kem_0d_length_secret_key 16
#define OQS_KEM_round5_r5n1_1kem_0d_length_ciphertext 5236
#define OQS_KEM_round5_r5n1_1kem_0d_length_shared_secret 16
OQS_KEM *OQS_KEM_round5_r5n1_1kem_0d_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_1kem_0d_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_1kem_0d_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_1kem_0d_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#ifdef OQS_ENABLE_KEM_round5_r5n1_3kem_0d
#define OQS_KEM_round5_r5n1_3kem_0d_length_public_key 8834
#define OQS_KEM_round5_r5n1_3kem_0d_length_secret_key 24
#define OQS_KEM_round5_r5n1_3kem_0d_length_ciphertext 8866
#define OQS_KEM_round5_r5n1_3kem_0d_length_shared_secret 24
OQS_KEM *OQS_KEM_round5_r5n1_3kem_0d_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_3kem_0d_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_3kem_0d_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_3kem_0d_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#ifdef OQS_ENABLE_KEM_round5_r5n1_5kem_0d
#define OQS_KEM_round5_r5n1_5kem_0d_length_public_key 14264
#define OQS_KEM_round5_r5n1_5kem_0d_length_secret_key 32
#define OQS_KEM_round5_r5n1_5kem_0d_length_ciphertext 14288
#define OQS_KEM_round5_r5n1_5kem_0d_length_shared_secret 32
OQS_KEM *OQS_KEM_round5_r5n1_5kem_0d_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_5kem_0d_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_5kem_0d_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_5kem_0d_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#ifdef OQS_ENABLE_KEM_round5_r5nd_1kem_0d
#define OQS_KEM_round5_r5nd_1kem_0d_length_public_key 634
#define OQS_KEM_round5_r5nd_1kem_0d_length_secret_key 16
#define OQS_KEM_round5_r5nd_1kem_0d_length_ciphertext 682
#define OQS_KEM_round5_r5nd_1kem_0d_length_shared_secret 16
OQS_KEM *OQS_KEM_round5_r5nd_1kem_0d_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_1kem_0d_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_1kem_0d_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_1kem_0d_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#ifdef OQS_ENABLE_KEM_round5_r5nd_3kem_0d
#define OQS_KEM_round5_r5nd_3kem_0d_length_public_key 909
#define OQS_KEM_round5_r5nd_3kem_0d_length_secret_key 24
#define OQS_KEM_round5_r5nd_3kem_0d_length_ciphertext 981
#define OQS_KEM_round5_r5nd_3kem_0d_length_shared_secret 24
OQS_KEM *OQS_KEM_round5_r5nd_3kem_0d_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_3kem_0d_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_3kem_0d_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_3kem_0d_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#ifdef OQS_ENABLE_KEM_round5_r5nd_3kem_5d
#define OQS_KEM_round5_r5nd_3kem_5d_length_public_key 780
#define OQS_KEM_round5_r5nd_3kem_5d_length_secret_key 24
#define OQS_KEM_round5_r5nd_3kem_5d_length_ciphertext 859
#define OQS_KEM_round5_r5nd_3kem_5d_length_shared_secret 24
OQS_KEM *OQS_KEM_round5_r5nd_3kem_5d_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_3kem_5d_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_3kem_5d_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_3kem_5d_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#ifdef OQS_ENABLE_KEM_round5_r5nd_5kem_0d
#define OQS_KEM_round5_r5nd_5kem_0d_length_public_key 1178
#define OQS_KEM_round5_r5nd_5kem_0d_length_secret_key 32
#define OQS_KEM_round5_r5nd_5kem_0d_length_ciphertext 1274
#define OQS_KEM_round5_r5nd_5kem_0d_length_shared_secret 32
OQS_KEM *OQS_KEM_round5_r5nd_5kem_0d_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_5kem_0d_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_5kem_0d_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_5kem_0d_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#ifdef OQS_ENABLE_KEM_round5_r5nd_5kem_5d
#define OQS_KEM_round5_r5nd_5kem_5d_length_public_key 972
#define OQS_KEM_round5_r5nd_5kem_5d_length_secret_key 32
#define OQS_KEM_round5_r5nd_5kem_5d_length_ciphertext 1063
#define OQS_KEM_round5_r5nd_5kem_5d_length_shared_secret 32
OQS_KEM *OQS_KEM_round5_r5nd_5kem_5d_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_5kem_5d_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_5kem_5d_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_5kem_5d_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#endif
