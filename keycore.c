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
 
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "keycore.h"

#define CMD_GET                 (0x00)
#define CMD_GET_VERSION         (0x01)
#define CMD_READ_PRO_STATUS     (0x02)
#define CMD_GET_ID              (0x03)
#define CMD_READ_DEVICE_PK      (0x11)
#define CMD_READ_SM_HASH        (0x12)
#define CMD_READ_SM_PK          (0x13)
#define CMD_READ_SM_SIGNA       (0x14)
#define CMD_GENERATE            (0x21)
#define CMD_SIGN                (0x31)

#define ACK     (0x79)
#define NACK    (0x1F)   

#define SEGMENT_BUFFER_LEN    (64)

enum {
  SEGMENT_TYPE_START = 0x00,
  SEGMENT_TYPE_NEXT  = 0x01,
  SEGMENT_TYPE_LAST  = 0x03
};

static uint8_t m_buffer[256];

static inline ssize_t 
write_byte(keycore_handle_t *handle, uint8_t c)
{
  return handle->writefn(&c, sizeof(c));
}

static inline int 
read_byte(keycore_handle_t *handle)
{
  uint8_t c;
  ssize_t byte_transferred;
  
  byte_transferred = handle->readfn(&c, sizeof(c));
  if (byte_transferred != sizeof(c)) {
    return -1;
  }
  
  return c;
}

static uint8_t
xorbuffer(const uint8_t *buffer, uint32_t size)
{
  uint32_t index;
  uint8_t result = 0x00;
  
  for (index = 0; index < size; index++) {
    result = result ^ buffer[index];
  }
  
  return result;
}

static void 
copy_to(uint8_t *dst, const uint8_t *src, uint32_t len)
{
  uint32_t index;
  for (index = 0; index < len; index++) {
    dst[index] = src[index];
  }
}

static keycore_status_t
send_command(keycore_handle_t *handle, int cmd) 
{
  uint8_t temp[2];
  ssize_t byte_transferred; 
  
  temp[0] = (uint8_t) cmd;
  temp[1] = (uint8_t) ~cmd;
  
  byte_transferred  = handle->writefn(&temp[0], 2);
  if (byte_transferred != 2) {
    return KEYCORE_ERROR_WRITE_FAILED;
  }
  
  return KEYCORE_OK;
}

static keycore_status_t
command_get(keycore_handle_t *handle, uint8_t *output) 
{
  int N;
  
  send_command(handle, CMD_GET);
  if (read_byte(handle) != ACK) {
    return KEYCORE_ERROR_RECV_NACK;
  }
  
  N = read_byte(handle);
  if (N > 0) {
    handle->readfn(output, N + 1);
  } else {
    return KEYCORE_ERROR_READ_FAILED;
  }
  
  if (read_byte(handle) != ACK) {
    return KEYCORE_ERROR_RECV_NACK;
  }
  
  return KEYCORE_OK;
}

static keycore_status_t
command_get_id(keycore_handle_t *handle, uint8_t *output)
{
  int N;
  
  send_command(handle, CMD_GET_ID);
  if (read_byte(handle) != ACK) {
    return KEYCORE_ERROR_RECV_NACK;
  }
  
  N = read_byte(handle);
  if (N > 0) {
    handle->readfn(output, N + 1);
  } else {
    return KEYCORE_ERROR_READ_FAILED;
  }
  
  if (read_byte(handle) != ACK) {
    return KEYCORE_ERROR_RECV_NACK;
  }
  
  return KEYCORE_OK;
}

static keycore_status_t
command_read_dev_pubkey(keycore_handle_t *handle, uint8_t *output)
{
  int N;
  
  send_command(handle, CMD_READ_DEVICE_PK);
  if (read_byte(handle) != ACK) {
    return KEYCORE_ERROR_RECV_NACK;
  }
  
  N = read_byte(handle);
  if (N > 0) {
    handle->readfn(output, N + 1);
  } else {
    return KEYCORE_ERROR_READ_FAILED;
  }
  
  if (read_byte(handle) != ACK) {
    return KEYCORE_ERROR_RECV_NACK;
  }
  
  return KEYCORE_OK;
}

static keycore_status_t
command_read_sm_hash(keycore_handle_t *handle, uint8_t *output)
{
  int N;
  
  send_command(handle, CMD_READ_SM_HASH);
  if (read_byte(handle) != ACK) {
    return KEYCORE_ERROR_RECV_NACK;
  }
  
  N = read_byte(handle);
  if (N > 0) {
    handle->readfn(output, N + 1);
  } else {
    return KEYCORE_ERROR_READ_FAILED;
  }
  
  if (read_byte(handle) != ACK) {
    return KEYCORE_ERROR_RECV_NACK;
  }
  
  return KEYCORE_OK;
}

static keycore_status_t
command_read_sm_pubkey(keycore_handle_t *handle, uint8_t *output)
{
  int N;
  
  send_command(handle, CMD_READ_SM_PK);
  if (read_byte(handle) != ACK) {
    return KEYCORE_ERROR_RECV_NACK;
  }
  
  N = read_byte(handle);
  if (N > 0) {
    handle->readfn(output, N + 1);
  } else {
    return KEYCORE_ERROR_READ_FAILED;
  }
  
  if (read_byte(handle) != ACK) {
    return KEYCORE_ERROR_RECV_NACK;
  }
  
  return KEYCORE_OK;
}

static keycore_status_t
command_read_sm_signa(keycore_handle_t *handle, uint8_t *output)
{
  int N;
  
  send_command(handle, CMD_READ_SM_SIGNA);
  if (read_byte(handle) != ACK) {
    return KEYCORE_ERROR_RECV_NACK;
  }
  
  N = read_byte(handle);
  if (N > 0) {
    handle->readfn(output, N + 1);
  } else {
    return KEYCORE_ERROR_READ_FAILED;
  }
  
  if (read_byte(handle) != ACK) {
    return KEYCORE_ERROR_RECV_NACK;
  }
  
  return KEYCORE_OK;
}

static uint32_t
segment_create(const uint8_t *buffer, uint16_t len, uint8_t seg_type, 
    uint8_t *output)
{
  int index;
  
  output[0] = len + 1;
  output[1] = seg_type;
  for (index = 0; index < len; index++) {
    output[2 + index] = buffer[index];
  }
  output[len + 2] = xorbuffer(output, len + 2);
  
  return (len + 3);
}

static keycore_status_t
command_generate(keycore_handle_t *handle, const uint8_t *program_bin,
    uint32_t progsize)
{
  send_command(handle, CMD_GENERATE);
  if (read_byte(handle) != ACK) {
    return KEYCORE_ERROR_RECV_NACK;
  }
  
  uint8_t progsize_bytes[5] = {
    (progsize >> 24) & 0xff,
    (progsize >> 16) & 0xff,
	(progsize >>  8) & 0xff,
	(progsize >>  0) & 0xff,
  };
  
  uint8_t checksum = progsize_bytes[0] ^ progsize_bytes[1] ^
        progsize_bytes[2] ^ progsize_bytes[3];
  
  progsize_bytes[4] = checksum;   
  handle->writefn(progsize_bytes, sizeof(progsize_bytes));
  
  if (read_byte(handle) != ACK) {
    return KEYCORE_ERROR_RECV_NACK;
  }
  
  int index;
  for (index = 0; index < progsize; index += SEGMENT_BUFFER_LEN) {
    if (index + SEGMENT_BUFFER_LEN < progsize) {
      uint32_t size = segment_create(program_bin + index, SEGMENT_BUFFER_LEN, 
          SEGMENT_TYPE_NEXT, m_buffer);
      handle->writefn(m_buffer, size);
    } else {
      uint32_t size = segment_create(program_bin + index, progsize - index,
          SEGMENT_TYPE_LAST, m_buffer);
      handle->writefn(m_buffer, size);
    }
    
    if (read_byte(handle) != ACK) {
      return KEYCORE_ERROR_RECV_NACK;
    }
  }
  
  if (read_byte(handle) != ACK) {
    return KEYCORE_ERROR_RECV_NACK;
  }
  
  return KEYCORE_OK;
}

static keycore_status_t
command_sign(keycore_handle_t *handle, const uint8_t *message, 
    uint32_t msgsize, uint8_t *output)
{
  send_command(handle, CMD_SIGN);
  if (read_byte(handle) != ACK) {
    return KEYCORE_ERROR_RECV_NACK;
  }
  
  uint8_t msgsize_bytes[5] = {
    (msgsize >> 24) & 0xff,
    (msgsize >> 16) & 0xff,
	(msgsize >>  8) & 0xff,
	(msgsize >>  0) & 0xff,
  };
  
  uint8_t checksum = msgsize_bytes[0] ^ msgsize_bytes[1] ^
      msgsize_bytes[2] ^ msgsize_bytes[3];
      
  msgsize_bytes[4] = checksum;
  handle->writefn(msgsize_bytes, sizeof(msgsize_bytes));
  
  if (read_byte(handle) != ACK) {
    return KEYCORE_ERROR_RECV_NACK;
  }
  
  int index;
  uint32_t size;
  for (index = 0; index < msgsize; index += SEGMENT_BUFFER_LEN) {
    if (index + SEGMENT_BUFFER_LEN < msgsize) {
      size = segment_create(message + index, SEGMENT_BUFFER_LEN, 
          SEGMENT_TYPE_NEXT, m_buffer);
      handle->writefn(m_buffer, size);
    } else {
      size = segment_create(message + index, msgsize - index,
          SEGMENT_TYPE_LAST, m_buffer);
      handle->writefn(m_buffer, size);
    }
    
    if (read_byte(handle) != ACK) {
      return KEYCORE_ERROR_RECV_NACK;
    }
  }
  
  if (read_byte(handle) != ACK) {
    return KEYCORE_ERROR_RECV_NACK;
  }
  
  int N;
  
  N = read_byte(handle);
  if (N > 0) {
    handle->readfn(m_buffer, N + 1);
  } else {
    return KEYCORE_ERROR_READ_FAILED;
  }
  
  if (read_byte(handle) != ACK) {
    return KEYCORE_ERROR_RECV_NACK;
  }
  
  copy_to(output, m_buffer, N + 1);
  
  return KEYCORE_OK;
}

keycore_status_t 
keycore_get_info(keycore_handle_t *handle, keycore_info_t *info)
{
  if (handle == NULL || info == NULL) {
    return KEYCORE_ERROR_NULLPTR;
  }
  
  int index;
  keycore_status_t status;
  
  status = command_get(handle, m_buffer);
  if (status != KEYCORE_OK) {
    return status;
  }
  
  info->version = m_buffer[0]; 
  for (index = 0; index < sizeof(info->cmds); index++) {
    info->cmds[index] = m_buffer[index + 1];
  }
  
  status = command_get_id(handle, info->id);
  if (status != KEYCORE_OK) {
    return status;
  }
  
  return KEYCORE_OK;
}

keycore_status_t 
keycore_get_devauth(keycore_handle_t *handle, keycore_authentication_t *auth)
{
  if (handle == NULL || auth != NULL) {
    return KEYCORE_ERROR_NULLPTR;
  }
  
  keycore_status_t status;
  
  status = command_read_dev_pubkey(handle, m_buffer);
  if (status != KEYCORE_OK) {
    return status;
  } 
  copy_to(auth->Dev_pubkey, m_buffer, sizeof(auth->Dev_pubkey));
  
  status = command_read_sm_pubkey(handle, m_buffer);
  if (status != KEYCORE_OK) {
    return status;
  }
  copy_to(auth->SM_pubkey, m_buffer, sizeof(auth->SM_pubkey));
  
  status = command_read_sm_hash(handle, m_buffer);
  if (status != KEYCORE_OK) {
    return status;
  }
  copy_to(auth->SM_hash, m_buffer, sizeof(auth->SM_hash));
 
  status = command_read_sm_signa(handle, m_buffer);
  if (status != KEYCORE_OK) {
    return status;
  }
  copy_to(auth->SM_signa, m_buffer, sizeof(auth->SM_signa));
  
  return KEYCORE_OK;
}

keycore_status_t 
keycore_build(keycore_handle_t *handle, const uint8_t *program_bin,
    uint32_t program_size)
{
  if (handle == NULL || program_bin == NULL) {
    return KEYCORE_ERROR_NULLPTR;
  }
  
  keycore_status_t status;
  
  status = command_generate(handle, program_bin, program_size);
  if (status != KEYCORE_OK) {
    return status;
  }
  
  return KEYCORE_OK;
}

keycore_status_t keycore_sign_message(keycore_handle_t *handle, const uint8_t *message,
    uint32_t message_size, uint8_t *output)
{
  if (handle == NULL || message == NULL) {
    return KEYCORE_ERROR_NULLPTR;
  }
  
  keycore_status_t status;
  
  status = command_sign(handle, message, message_size, output);
  if (status != KEYCORE_OK) {
    return status;
  }
  
  return KEYCORE_OK;
}



