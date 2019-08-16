#ifndef __OQS_KEM_ROUND5_H
#define __OQS_KEM_ROUND5_H

#include <oqs/oqs.h>

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

#ifdef OQS_ENABLE_KEM_round5_r5nd_0kem_2iot
#define OQS_KEM_round5_r5nd_0kem_2iot_length_public_key 342
#define OQS_KEM_round5_r5nd_0kem_2iot_length_secret_key 16
#define OQS_KEM_round5_r5nd_0kem_2iot_length_ciphertext 394
#define OQS_KEM_round5_r5nd_0kem_2iot_length_shared_secret 16
OQS_KEM *OQS_KEM_round5_r5nd_0kem_2iot_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_0kem_2iot_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_0kem_2iot_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_0kem_2iot_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#ifdef OQS_ENABLE_KEM_round5_r5nd_1kem_5d
#define OQS_KEM_round5_r5nd_1kem_5d_length_public_key 445
#define OQS_KEM_round5_r5nd_1kem_5d_length_secret_key 16
#define OQS_KEM_round5_r5nd_1kem_5d_length_ciphertext 549
#define OQS_KEM_round5_r5nd_1kem_5d_length_shared_secret 16
OQS_KEM *OQS_KEM_round5_r5nd_1kem_5d_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_1kem_5d_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_1kem_5d_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_1kem_5d_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
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

#ifdef OQS_ENABLE_KEM_round5_r5nd_1kem_4longkey
#define OQS_KEM_round5_r5nd_1kem_4longkey_length_public_key 453
#define OQS_KEM_round5_r5nd_1kem_4longkey_length_secret_key 24
#define OQS_KEM_round5_r5nd_1kem_4longkey_length_ciphertext 563
#define OQS_KEM_round5_r5nd_1kem_4longkey_length_shared_secret 24
OQS_KEM *OQS_KEM_round5_r5nd_1kem_4longkey_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_1kem_4longkey_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_1kem_4longkey_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_1kem_4longkey_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
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

#ifdef OQS_ENABLE_KEM_round5_r5n1_3ccakem_0smallct
#define OQS_KEM_round5_r5n1_3ccakem_0smallct_length_public_key 163536
#define OQS_KEM_round5_r5n1_3ccakem_0smallct_length_secret_key 163584
#define OQS_KEM_round5_r5n1_3ccakem_0smallct_length_ciphertext 964
#define OQS_KEM_round5_r5n1_3ccakem_0smallct_length_shared_secret 24
OQS_KEM *OQS_KEM_round5_r5n1_3ccakem_0smallct_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_3ccakem_0smallct_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_3ccakem_0smallct_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_3ccakem_0smallct_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#ifdef OQS_ENABLE_KEM_round5_r5nd_5ccakem_0d
#define OQS_KEM_round5_r5nd_5ccakem_0d_length_public_key 1349
#define OQS_KEM_round5_r5nd_5ccakem_0d_length_secret_key 1413
#define OQS_KEM_round5_r5nd_5ccakem_0d_length_ciphertext 1493
#define OQS_KEM_round5_r5nd_5ccakem_0d_length_shared_secret 32
OQS_KEM *OQS_KEM_round5_r5nd_5ccakem_0d_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_5ccakem_0d_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_5ccakem_0d_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_5ccakem_0d_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#ifdef OQS_ENABLE_KEM_round5_r5nd_3ccakem_0d
#define OQS_KEM_round5_r5nd_3ccakem_0d_length_public_key 983
#define OQS_KEM_round5_r5nd_3ccakem_0d_length_secret_key 1031
#define OQS_KEM_round5_r5nd_3ccakem_0d_length_ciphertext 1095
#define OQS_KEM_round5_r5nd_3ccakem_0d_length_shared_secret 24
OQS_KEM *OQS_KEM_round5_r5nd_3ccakem_0d_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_3ccakem_0d_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_3ccakem_0d_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_3ccakem_0d_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#ifdef OQS_ENABLE_KEM_round5_r5nd_5ccakem_5d
#define OQS_KEM_round5_r5nd_5ccakem_5d_length_public_key 978
#define OQS_KEM_round5_r5nd_5ccakem_5d_length_secret_key 1042
#define OQS_KEM_round5_r5nd_5ccakem_5d_length_ciphertext 1269
#define OQS_KEM_round5_r5nd_5ccakem_5d_length_shared_secret 32
OQS_KEM *OQS_KEM_round5_r5nd_5ccakem_5d_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_5ccakem_5d_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_5ccakem_5d_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_5ccakem_5d_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#ifdef OQS_ENABLE_KEM_round5_r5nd_1ccakem_5d
#define OQS_KEM_round5_r5nd_1ccakem_5d_length_public_key 461
#define OQS_KEM_round5_r5nd_1ccakem_5d_length_secret_key 493
#define OQS_KEM_round5_r5nd_1ccakem_5d_length_ciphertext 620
#define OQS_KEM_round5_r5nd_1ccakem_5d_length_shared_secret 16
OQS_KEM *OQS_KEM_round5_r5nd_1ccakem_5d_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_1ccakem_5d_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_1ccakem_5d_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_1ccakem_5d_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#ifdef OQS_ENABLE_KEM_round5_r5nd_1ccakem_0d
#define OQS_KEM_round5_r5nd_1ccakem_0d_length_public_key 676
#define OQS_KEM_round5_r5nd_1ccakem_0d_length_secret_key 708
#define OQS_KEM_round5_r5nd_1ccakem_0d_length_ciphertext 740
#define OQS_KEM_round5_r5nd_1ccakem_0d_length_shared_secret 16
OQS_KEM *OQS_KEM_round5_r5nd_1ccakem_0d_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_1ccakem_0d_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_1ccakem_0d_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_1ccakem_0d_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#ifdef OQS_ENABLE_KEM_round5_r5n1_3ccakem_0d
#define OQS_KEM_round5_r5n1_3ccakem_0d_length_public_key 9660
#define OQS_KEM_round5_r5n1_3ccakem_0d_length_secret_key 9708
#define OQS_KEM_round5_r5n1_3ccakem_0d_length_ciphertext 9708
#define OQS_KEM_round5_r5n1_3ccakem_0d_length_shared_secret 24
OQS_KEM *OQS_KEM_round5_r5n1_3ccakem_0d_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_3ccakem_0d_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_3ccakem_0d_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_3ccakem_0d_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#ifdef OQS_ENABLE_KEM_round5_r5nd_3ccakem_5d
#define OQS_KEM_round5_r5nd_3ccakem_5d_length_public_key 780
#define OQS_KEM_round5_r5nd_3ccakem_5d_length_secret_key 828
#define OQS_KEM_round5_r5nd_3ccakem_5d_length_ciphertext 926
#define OQS_KEM_round5_r5nd_3ccakem_5d_length_shared_secret 24
OQS_KEM *OQS_KEM_round5_r5nd_3ccakem_5d_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_3ccakem_5d_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_3ccakem_5d_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5nd_3ccakem_5d_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#ifdef OQS_ENABLE_KEM_round5_r5n1_5ccakem_0d
#define OQS_KEM_round5_r5n1_5ccakem_0d_length_public_key 14636
#define OQS_KEM_round5_r5n1_5ccakem_0d_length_secret_key 14700
#define OQS_KEM_round5_r5n1_5ccakem_0d_length_ciphertext 14692
#define OQS_KEM_round5_r5n1_5ccakem_0d_length_shared_secret 32
OQS_KEM *OQS_KEM_round5_r5n1_5ccakem_0d_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_5ccakem_0d_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_5ccakem_0d_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_5ccakem_0d_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#ifdef OQS_ENABLE_KEM_round5_r5n1_1ccakem_0d
#define OQS_KEM_round5_r5n1_1ccakem_0d_length_public_key 5740
#define OQS_KEM_round5_r5n1_1ccakem_0d_length_secret_key 5772
#define OQS_KEM_round5_r5n1_1ccakem_0d_length_ciphertext 5788
#define OQS_KEM_round5_r5n1_1ccakem_0d_length_shared_secret 16
OQS_KEM *OQS_KEM_round5_r5n1_1ccakem_0d_new();
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_1ccakem_0d_keypair(uint8_t *public_key, uint8_t *secret_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_1ccakem_0d_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);
OQS_API OQS_STATUS OQS_KEM_round5_r5n1_1ccakem_0d_decaps(uint8_t *shared_secret, const unsigned char *ciphertext, const uint8_t *secret_key);
#endif

#endif
