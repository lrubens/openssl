/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include "packeted_bio.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>


namespace {

const uint8_t kOpcodePacket = 'P';
const uint8_t kOpcodeTimeout = 'T';

// ReadAll reads |len| bytes from |bio| into |out|. It returns 1 on success and
// 0 or -1 on error.
static int ReadAll(BIO *bio, uint8_t *out, size_t len) {
  while (len > 0) {
    int chunk_len = INT_MAX;
    if (len <= INT_MAX) {
      chunk_len = (int)len;
    }
    int ret = BIO_read(bio, out, chunk_len);
    if (ret <= 0) {
      return ret;
    }
    out += ret;
    len -= ret;
  }
  return 1;
}

static int PacketedWrite(BIO *bio, const char *in, int inl) {
  if (BIO_next(bio) == NULL) {
    return 0;
  }

  BIO_clear_retry_flags(bio);

  // Write the header.
  uint8_t header[5];
  header[0] = kOpcodePacket;
  header[1] = (inl >> 24) & 0xff;
  header[2] = (inl >> 16) & 0xff;
  header[3] = (inl >> 8) & 0xff;
  header[4] = inl & 0xff;
  int ret = BIO_write(BIO_next(bio), header, sizeof(header));
  if (ret <= 0) {
    BIO_copy_next_retry(bio);
    return ret;
  }

  // Write the buffer.
  ret = BIO_write(BIO_next(bio), in, inl);
  if (ret < 0 || (inl > 0 && ret == 0)) {
    BIO_copy_next_retry(bio);
    return ret;
  }
  assert(ret == inl);
  return ret;
}

static int PacketedRead(BIO *bio, char *out, int outl) {
  if (BIO_next(bio) == NULL) {
    return 0;
  }

  BIO_clear_retry_flags(bio);

  // Read the opcode.
  uint8_t opcode;
  int ret = ReadAll(BIO_next(bio), &opcode, sizeof(opcode));
  if (ret <= 0) {
    BIO_copy_next_retry(bio);
    return ret;
  }

  if (opcode == kOpcodeTimeout) {
    fprintf(stderr, "Timeout simulation not supported.\n");
    return -1;
  }

  if (opcode != kOpcodePacket) {
    fprintf(stderr, "Unknown opcode, %u\n", opcode);
    return -1;
  }

  // Read the length prefix.
  uint8_t len_bytes[4];
  ret = ReadAll(BIO_next(bio), len_bytes, sizeof(len_bytes));
  if (ret <= 0) {
    BIO_copy_next_retry(bio);
    return ret;
  }

  uint32_t len = (len_bytes[0] << 24) | (len_bytes[1] << 16) |
      (len_bytes[2] << 8) | len_bytes[3];
  uint8_t *buf = (uint8_t *)OPENSSL_malloc(len);
  if (buf == NULL) {
    return -1;
  }
  ret = ReadAll(BIO_next(bio), buf, len);
  if (ret <= 0) {
    fprintf(stderr, "Packeted BIO was truncated\n");
    return -1;
  }

  if (outl > (int)len) {
    outl = len;
  }
  memcpy(out, buf, outl);
  OPENSSL_free(buf);
  return outl;
}

static long PacketedCtrl(BIO *bio, int cmd, long num, void *ptr) {
  if (BIO_next(bio) == NULL) {
    return 0;
  }
  BIO_clear_retry_flags(bio);
  int ret = BIO_ctrl(BIO_next(bio), cmd, num, ptr);
  BIO_copy_next_retry(bio);
  return ret;
}

static int PacketedNew(BIO *bio) {
  BIO_set_init(bio, 1);
  return 1;
}

static int PacketedFree(BIO *bio) {
  if (bio == NULL) {
    return 0;
  }

  BIO_set_init(bio, 0);
  return 1;
}

static long PacketedCallbackCtrl(BIO *bio, int cmd, bio_info_cb fp) {
  if (BIO_next(bio) == NULL) {
    return 0;
  }
  return BIO_callback_ctrl(BIO_next(bio), cmd, fp);
}

static BIO_METHOD *g_packeted_bio_method = NULL;

static const BIO_METHOD *PacketedMethod(void)
{
  if (g_packeted_bio_method == NULL) {
    g_packeted_bio_method = BIO_meth_new(BIO_TYPE_FILTER, "packeted bio");
    if (   g_packeted_bio_method == NULL
        || !BIO_meth_set_write(g_packeted_bio_method, PacketedWrite)
        || !BIO_meth_set_read(g_packeted_bio_method, PacketedRead)
        || !BIO_meth_set_ctrl(g_packeted_bio_method, PacketedCtrl)
        || !BIO_meth_set_create(g_packeted_bio_method, PacketedNew)
        || !BIO_meth_set_destroy(g_packeted_bio_method, PacketedFree)
        || !BIO_meth_set_callback_ctrl(g_packeted_bio_method,
                                       PacketedCallbackCtrl))
    return NULL;
  }
  return g_packeted_bio_method;
}
}  // namespace

ScopedBIO PacketedBioCreate(timeval *out_timeout) {
  ScopedBIO bio(BIO_new(PacketedMethod()));
  if (!bio) {
    return nullptr;
  }
  BIO_set_data(bio.get(), out_timeout);
  return bio;
}