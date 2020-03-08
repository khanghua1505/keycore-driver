/* Copyright (c) 2019 - 2020, Khang Hua, email: khanghua1505@gmail.com
 * All right reserved.
 *
 * This file is written and modified by Khang Hua.
 *
 * This model is free software; you can redistribute it and/or modify it under the terms
 * of the GNU Lesser General Public License; either version 2.1 of the License, or (at your option)
 * any later version. See the GNU Lesser General Public License for more details,
 *
 * This model is distributed in the hope that it will be useful.
 */

#ifndef _KEYSTONE_KEYCORE_H_
#define _KEYSTONE_KEYCORE_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

typedef enum {
  KEYCORE_OK,
  KEYCORE_ERROR_TIMEOUT,
  KEYCORE_ERROR_NULLPTR,
  KEYCORE_ERROR_INVALID,
  KEYCORE_ERROR_READ_FAILED,
  KEYCORE_ERROR_WRITE_FAILED,
  KEYCORE_ERROR_RECV_NACK,
}
keycore_status_t;

typedef int (*keycore_init_t)(void);
typedef ssize_t (*keycore_write_t)(const uint8_t* buffer, uint16_t len);
typedef ssize_t (*keycore_read_t)(uint8_t *buffer, uint16_t len);

typedef uint8_t keycore_version_t;
typedef uint8_t keycore_id_t;

typedef struct {
  keycore_version_t version;
  uint8_t id[2];
  uint8_t cmds[9];
}
keycore_info_t;

/*
 * Note: Can not get Security Monitor Private key and Manufacture Private key.
 */
typedef struct {
  uint8_t Dev_pubkey[32];        ///< Manufacture public key.
  uint8_t SM_pubkey[32];         ///< Security Monitor public key.
  uint8_t SM_hash[64];           ///< Security Monitor hash.
  uint8_t SM_signa[64];          ///< Security Monitor Signature.
}
keycore_authentication_t;

typedef struct {
  keycore_init_t initfn;
  keycore_write_t writefn;
  keycore_read_t readfn;
}
keycore_handle_t;

extern keycore_handle_t keycore;

keycore_status_t keycore_get_info(keycore_handle_t *handle, keycore_info_t *info);
keycore_status_t keycore_get_devauth(keycore_handle_t *handle, 
    keycore_authentication_t *auth);
keycore_status_t keycore_build(keycore_handle_t *handle, const uint8_t *program_bin,
    uint32_t program_size);
keycore_status_t keycore_sign_message(keycore_handle_t *handle, const uint8_t *message,
    uint32_t messgae_size, uint8_t *output);
keycore_status_t keycore_attest_message(keycore_handle_t *handle, const uint8_t *message,
    uint8_t message_size, keycore_authentication_t *auth);

#ifdef __cplusplus
}
#endif  // __cpluscplus

#endif  // _KEYSTONE_KEYCORE_H_

