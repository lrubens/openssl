/* Extra OQS content for the ssl integration */

/* Returns the OQS KEM NID from a given alg name, or 0 if there is no match */
static int OQS_nid_from_string(const char *value) {
  int nid = 0;
  int len = strlen(value);
  if (strncmp(value,"oqs_kem_default", len) == 0) {
    nid = NID_OQS_KEM_DEFAULT;
///// OQS_TEMPLATE_FRAGMENT_NID_FROM_STRING_START
  } else if (strncmp(value, "frodo640aes", len) == 0) {
    nid = NID_OQS_frodo640aes;
  } else if (strncmp(value, "frodo640shake", len) == 0) {
    nid = NID_OQS_frodo640shake;
  } else if (strncmp(value, "frodo976aes", len) == 0) {
    nid = NID_OQS_frodo976aes;
  } else if (strncmp(value, "frodo976shake", len) == 0) {
    nid = NID_OQS_frodo976shake;
  } else if (strncmp(value, "frodo1344aes", len) == 0) {
    nid = NID_OQS_frodo1344aes;
  } else if (strncmp(value, "frodo1344shake", len) == 0) {
    nid = NID_OQS_frodo1344shake;
  } else if (strncmp(value, "bike1l1", len) == 0) {
    nid = NID_OQS_bike1l1;
  } else if (strncmp(value, "bike1l3", len) == 0) {
    nid = NID_OQS_bike1l3;
  } else if (strncmp(value, "bike1l5", len) == 0) {
    nid = NID_OQS_bike1l5;
  } else if (strncmp(value, "bike2l1", len) == 0) {
    nid = NID_OQS_bike2l1;
  } else if (strncmp(value, "bike2l3", len) == 0) {
    nid = NID_OQS_bike2l3;
  } else if (strncmp(value, "bike2l5", len) == 0) {
    nid = NID_OQS_bike2l5;
  } else if (strncmp(value, "bike3l1", len) == 0) {
    nid = NID_OQS_bike3l1;
  } else if (strncmp(value, "bike3l3", len) == 0) {
    nid = NID_OQS_bike3l3;
  } else if (strncmp(value, "bike3l5", len) == 0) {
    nid = NID_OQS_bike3l5;
  } else if (strncmp(value, "kyber512", len) == 0) {
    nid = NID_OQS_kyber512;
  } else if (strncmp(value, "kyber768", len) == 0) {
    nid = NID_OQS_kyber768;
  } else if (strncmp(value, "kyber1024", len) == 0) {
    nid = NID_OQS_kyber1024;
  } else if (strncmp(value, "newhope512cca", len) == 0) {
    nid = NID_OQS_newhope512cca;
  } else if (strncmp(value, "newhope1024cca", len) == 0) {
    nid = NID_OQS_newhope1024cca;
  } else if (strncmp(value, "ntru_hps2048509", len) == 0) {
    nid = NID_OQS_ntru_hps2048509;
  } else if (strncmp(value, "ntru_hps2048677", len) == 0) {
    nid = NID_OQS_ntru_hps2048677;
  } else if (strncmp(value, "ntru_hps4096821", len) == 0) {
    nid = NID_OQS_ntru_hps4096821;
  } else if (strncmp(value, "ntru_hrss701", len) == 0) {
    nid = NID_OQS_ntru_hrss701;
  } else if (strncmp(value, "lightsaber", len) == 0) {
    nid = NID_OQS_lightsaber;
  } else if (strncmp(value, "saber", len) == 0) {
    nid = NID_OQS_saber;
  } else if (strncmp(value, "firesaber", len) == 0) {
    nid = NID_OQS_firesaber;
  } else if (strncmp(value, "sidhp434", len) == 0) {
    nid = NID_OQS_sidhp434;
  } else if (strncmp(value, "sidhp503", len) == 0) {
    nid = NID_OQS_sidhp503;
  } else if (strncmp(value, "sidhp610", len) == 0) {
    nid = NID_OQS_sidhp610;
  } else if (strncmp(value, "sidhp751", len) == 0) {
    nid = NID_OQS_sidhp751;
  } else if (strncmp(value, "sikep434", len) == 0) {
    nid = NID_OQS_sikep434;
  } else if (strncmp(value, "sikep503", len) == 0) {
    nid = NID_OQS_sikep503;
  } else if (strncmp(value, "sikep610", len) == 0) {
    nid = NID_OQS_sikep610;
  } else if (strncmp(value, "sikep751", len) == 0) {
    nid = NID_OQS_sikep751;
  } else if (strncmp(value, "round5_r5nd_1kem_0d", len) == 0) {
    nid = NID_OQS_round5_r5nd_1kem_0d;
  } else if (strncmp(value, "round5_r5nd_0kem_2iot", len) == 0) {
    nid = NID_OQS_round5_r5nd_0kem_2iot;
  } else if (strncmp(value, "round5_r5nd_1kem_5d", len) == 0) {
    nid = NID_OQS_round5_r5nd_1kem_5d;
  } else if (strncmp(value, "round5_r5nd_5kem_0d", len) == 0) {
    nid = NID_OQS_round5_r5nd_5kem_0d;
  } else if (strncmp(value, "round5_r5nd_1kem_4longkey", len) == 0) {
    nid = NID_OQS_round5_r5nd_1kem_4longkey;
  } else if (strncmp(value, "round5_r5nd_3kem_5d", len) == 0) {
    nid = NID_OQS_round5_r5nd_3kem_5d;
  } else if (strncmp(value, "round5_r5n1_3kem_0d", len) == 0) {
    nid = NID_OQS_round5_r5n1_3kem_0d;
  } else if (strncmp(value, "round5_r5n1_1kem_0d", len) == 0) {
    nid = NID_OQS_round5_r5n1_1kem_0d;
  } else if (strncmp(value, "round5_r5n1_5kem_0d", len) == 0) {
    nid = NID_OQS_round5_r5n1_5kem_0d;
  } else if (strncmp(value, "round5_r5nd_3kem_0d", len) == 0) {
    nid = NID_OQS_round5_r5nd_3kem_0d;
  } else if (strncmp(value, "round5_r5nd_5kem_5d", len) == 0) {
    nid = NID_OQS_round5_r5nd_5kem_5d;
  } else if (strncmp(value, "round5_r5n1_3ccakem_0smallct", len) == 0) {
    nid = NID_OQS_round5_r5n1_3ccakem_0smallct;
  } else if (strncmp(value, "round5_r5nd_5ccakem_0d", len) == 0) {
    nid = NID_OQS_round5_r5nd_5ccakem_0d;
  } else if (strncmp(value, "round5_r5nd_3ccakem_0d", len) == 0) {
    nid = NID_OQS_round5_r5nd_3ccakem_0d;
  } else if (strncmp(value, "round5_r5nd_5ccakem_5d", len) == 0) {
    nid = NID_OQS_round5_r5nd_5ccakem_5d;
  } else if (strncmp(value, "round5_r5nd_1ccakem_5d", len) == 0) {
    nid = NID_OQS_round5_r5nd_1ccakem_5d;
  } else if (strncmp(value, "round5_r5nd_1ccakem_0d", len) == 0) {
    nid = NID_OQS_round5_r5nd_1ccakem_0d;
  } else if (strncmp(value, "round5_r5n1_3ccakem_0d", len) == 0) {
    nid = NID_OQS_round5_r5n1_3ccakem_0d;
  } else if (strncmp(value, "round5_r5nd_3ccakem_5d", len) == 0) {
    nid = NID_OQS_round5_r5nd_3ccakem_5d;
  } else if (strncmp(value, "round5_r5n1_5ccakem_0d", len) == 0) {
    nid = NID_OQS_round5_r5n1_5ccakem_0d;
  } else if (strncmp(value, "round5_r5n1_1ccakem_0d", len) == 0) {
    nid = NID_OQS_round5_r5n1_1ccakem_0d;
///// OQS_TEMPLATE_FRAGMENT_NID_FROM_STRING_END
  /* hybrid algs */
  } else if (strncmp(value,"p256-oqs_kem_default", len) == 0) {
    nid = NID_OQS_p256_KEM_DEFAULT;
///// OQS_TEMPLATE_FRAGMENT_NID_FROM_STRING_HYBRID_START
  } else if (strncmp(value, "p256-frodo640aes", len) == 0) {
    nid = NID_OQS_p256_frodo640aes;
  } else if (strncmp(value, "p256-frodo640shake", len) == 0) {
    nid = NID_OQS_p256_frodo640shake;
  } else if (strncmp(value, "p256-frodo976aes", len) == 0) {
    nid = NID_OQS_p256_frodo976aes;
  } else if (strncmp(value, "p256-frodo976shake", len) == 0) {
    nid = NID_OQS_p256_frodo976shake;
  } else if (strncmp(value, "p256-frodo1344aes", len) == 0) {
    nid = NID_OQS_p256_frodo1344aes;
  } else if (strncmp(value, "p256-frodo1344shake", len) == 0) {
    nid = NID_OQS_p256_frodo1344shake;
  } else if (strncmp(value, "p256-bike1l1", len) == 0) {
    nid = NID_OQS_p256_bike1l1;
  } else if (strncmp(value, "p256-bike1l3", len) == 0) {
    nid = NID_OQS_p256_bike1l3;
  } else if (strncmp(value, "p256-bike1l5", len) == 0) {
    nid = NID_OQS_p256_bike1l5;
  } else if (strncmp(value, "p256-bike2l1", len) == 0) {
    nid = NID_OQS_p256_bike2l1;
  } else if (strncmp(value, "p256-bike2l3", len) == 0) {
    nid = NID_OQS_p256_bike2l3;
  } else if (strncmp(value, "p256-bike2l5", len) == 0) {
    nid = NID_OQS_p256_bike2l5;
  } else if (strncmp(value, "p256-bike3l1", len) == 0) {
    nid = NID_OQS_p256_bike3l1;
  } else if (strncmp(value, "p256-bike3l3", len) == 0) {
    nid = NID_OQS_p256_bike3l3;
  } else if (strncmp(value, "p256-bike3l5", len) == 0) {
    nid = NID_OQS_p256_bike3l5;
  } else if (strncmp(value, "p256-kyber512", len) == 0) {
    nid = NID_OQS_p256_kyber512;
  } else if (strncmp(value, "p256-kyber768", len) == 0) {
    nid = NID_OQS_p256_kyber768;
  } else if (strncmp(value, "p256-kyber1024", len) == 0) {
    nid = NID_OQS_p256_kyber1024;
  } else if (strncmp(value, "p256-newhope512cca", len) == 0) {
    nid = NID_OQS_p256_newhope512cca;
  } else if (strncmp(value, "p256-newhope1024cca", len) == 0) {
    nid = NID_OQS_p256_newhope1024cca;
  } else if (strncmp(value, "p256-ntru_hps2048509", len) == 0) {
    nid = NID_OQS_p256_ntru_hps2048509;
  } else if (strncmp(value, "p256-ntru_hps2048677", len) == 0) {
    nid = NID_OQS_p256_ntru_hps2048677;
  } else if (strncmp(value, "p256-ntru_hps4096821", len) == 0) {
    nid = NID_OQS_p256_ntru_hps4096821;
  } else if (strncmp(value, "p256-ntru_hrss701", len) == 0) {
    nid = NID_OQS_p256_ntru_hrss701;
  } else if (strncmp(value, "p256-lightsaber", len) == 0) {
    nid = NID_OQS_p256_lightsaber;
  } else if (strncmp(value, "p256-saber", len) == 0) {
    nid = NID_OQS_p256_saber;
  } else if (strncmp(value, "p256-firesaber", len) == 0) {
    nid = NID_OQS_p256_firesaber;
  } else if (strncmp(value, "p256-sidhp434", len) == 0) {
    nid = NID_OQS_p256_sidhp434;
  } else if (strncmp(value, "p256-sidhp503", len) == 0) {
    nid = NID_OQS_p256_sidhp503;
  } else if (strncmp(value, "p256-sidhp610", len) == 0) {
    nid = NID_OQS_p256_sidhp610;
  } else if (strncmp(value, "p256-sidhp751", len) == 0) {
    nid = NID_OQS_p256_sidhp751;
  } else if (strncmp(value, "p256-sikep434", len) == 0) {
    nid = NID_OQS_p256_sikep434;
  } else if (strncmp(value, "p256-sikep503", len) == 0) {
    nid = NID_OQS_p256_sikep503;
  } else if (strncmp(value, "p256-sikep610", len) == 0) {
    nid = NID_OQS_p256_sikep610;
  } else if (strncmp(value, "p256-sikep751", len) == 0) {
    nid = NID_OQS_p256_sikep751;
  } else if (strncmp(value, "p256-round5_r5nd_1kem_0d", len) == 0) {
    nid = NID_OQS_p256_round5_r5nd_1kem_0d;
  } else if (strncmp(value, "p256-round5_r5nd_0kem_2iot", len) == 0) {
    nid = NID_OQS_p256_round5_r5nd_0kem_2iot;
  } else if (strncmp(value, "p256-round5_r5nd_1kem_5d", len) == 0) {
    nid = NID_OQS_p256_round5_r5nd_1kem_5d;
  } else if (strncmp(value, "p256-round5_r5nd_5kem_0d", len) == 0) {
    nid = NID_OQS_p256_round5_r5nd_5kem_0d;
  } else if (strncmp(value, "p256-round5_r5nd_1kem_4longkey", len) == 0) {
    nid = NID_OQS_p256_round5_r5nd_1kem_4longkey;
  } else if (strncmp(value, "p256-round5_r5nd_3kem_5d", len) == 0) {
    nid = NID_OQS_p256_round5_r5nd_3kem_5d;
  } else if (strncmp(value, "p256-round5_r5n1_3kem_0d", len) == 0) {
    nid = NID_OQS_p256_round5_r5n1_3kem_0d;
  } else if (strncmp(value, "p256-round5_r5n1_1kem_0d", len) == 0) {
    nid = NID_OQS_p256_round5_r5n1_1kem_0d;
  } else if (strncmp(value, "p256-round5_r5n1_5kem_0d", len) == 0) {
    nid = NID_OQS_p256_round5_r5n1_5kem_0d;
  } else if (strncmp(value, "p256-round5_r5nd_3kem_0d", len) == 0) {
    nid = NID_OQS_p256_round5_r5nd_3kem_0d;
  } else if (strncmp(value, "p256-round5_r5nd_5kem_5d", len) == 0) {
    nid = NID_OQS_p256_round5_r5nd_5kem_5d;
  } else if (strncmp(value, "p256-round5_r5n1_3ccakem_0smallct", len) == 0) {
    nid = NID_OQS_p256_round5_r5n1_3ccakem_0smallct;
  } else if (strncmp(value, "p256-round5_r5nd_5ccakem_0d", len) == 0) {
    nid = NID_OQS_p256_round5_r5nd_5ccakem_0d;
  } else if (strncmp(value, "p256-round5_r5nd_3ccakem_0d", len) == 0) {
    nid = NID_OQS_p256_round5_r5nd_3ccakem_0d;
  } else if (strncmp(value, "p256-round5_r5nd_5ccakem_5d", len) == 0) {
    nid = NID_OQS_p256_round5_r5nd_5ccakem_5d;
  } else if (strncmp(value, "p256-round5_r5nd_1ccakem_5d", len) == 0) {
    nid = NID_OQS_p256_round5_r5nd_1ccakem_5d;
  } else if (strncmp(value, "p256-round5_r5nd_1ccakem_0d", len) == 0) {
    nid = NID_OQS_p256_round5_r5nd_1ccakem_0d;
  } else if (strncmp(value, "p256-round5_r5n1_3ccakem_0d", len) == 0) {
    nid = NID_OQS_p256_round5_r5n1_3ccakem_0d;
  } else if (strncmp(value, "p256-round5_r5nd_3ccakem_5d", len) == 0) {
    nid = NID_OQS_p256_round5_r5nd_3ccakem_5d;
  } else if (strncmp(value, "p256-round5_r5n1_5ccakem_0d", len) == 0) {
    nid = NID_OQS_p256_round5_r5n1_5ccakem_0d;
  } else if (strncmp(value, "p256-round5_r5n1_1ccakem_0d", len) == 0) {
    nid = NID_OQS_p256_round5_r5n1_1ccakem_0d;
///// OQS_TEMPLATE_FRAGMENT_NID_FROM_STRING_HYBRID_END
  }
  return nid;
}
