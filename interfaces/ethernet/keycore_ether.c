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
#include <string.h>
#include "spi.h"
#include "socket.h"
#include "keycore.h"

#define KEYCORE_SOCKET       (0)
#define KEYCORE_PORT         (8080)
#define KEYCORE_SERVER_IP    { 10, 10, 10, 225 }

static uint8_t  keycore_socket = KEYCORE_SOCKET;
static uint16_t keycore_port = KEYCORE_PORT;
static uint8_t  keycore_serverip[] =  KEYCORE_SERVER_IP;

static wiz_NetInfo net_info;
static uint8_t chip_txrx_buffsize[] = {2, 2, 2, 2, 2, 2, 2, 2};

static const uint8_t IP[4] = { 10, 10, 10, 2 };
static const uint8_t MAC_ADDR[6] = { 0xEA, 0x11, 0x22, 0x33, 0x44, 0xEA };
static const uint8_t GATEWAY[4] = { 10, 10, 10, 225 };
static const uint8_t SUBNET_MASK[4] = { 255, 255, 255, 0 };

static void 
spi_select(void)
{
  stm32f1_spi_select();
}

static void
spi_deselect(void)
{
  stm32f1_spi_deselect();
}

static void 
spi_read(uint8_t *buffer, uint16_t len)
{
  stm32f1_spi_read(buffer, len);
}

static void 
spi_write(uint8_t *buffer, uint16_t len)
{
  stm32f1_spi_write(buffer, len);
}

static uint8_t 
spi_read_byte(void)
{
  return stm32f1_spi_readbyte();
}

static void
spi_write_byte(uint8_t byte)
{
  stm32f1_spi_writebyte(byte);
}

static int
chip_init(void)
{
  int8_t status;
  
  memcpy(net_info.ip, IP, 4);
  memcpy(net_info.mac, MAC_ADDR, 6);
  memcpy(net_info.gw, GATEWAY, 4);
  memcpy(net_info.sn, SUBNET_MASK, 4);
  
  reg_wizchip_cs_cbfunc(spi_select, spi_deselect);
  reg_wizchip_spi_cbfunc(spi_read_byte, spi_write_byte);
  reg_wizchip_spiburst_cbfunc(spi_read, spi_write);
  
  status = wizchip_init(chip_txrx_buffsize, chip_txrx_buffsize);
  if (status != 0) {
    return -1;
  }
  
  setSHAR(net_info.mac);
  wizchip_setnetinfo(&net_info);
  
  return 0;
}

static int
ethernet_init(void)
{
  uint8_t status;
  
  if (chip_init() != 0) {
    return -1;
  }
  
  status = socket(keycore_socket, Sn_MR_TCP, keycore_port, 0);
  if (status != keycore_socket) {
    return -1;
  }
  
  status = connect(keycore_socket, keycore_serverip, keycore_port);
  if (status != SOCK_OK) {
    close(keycore_socket);
    return -1;
  }
  
  return 0;
}

static ssize_t
ethernet_write(const uint8_t *buffer, uint16_t len)
{
  ssize_t byte_transferred;
  
  byte_transferred = send(keycore_socket, buffer, len);
  if (byte_transferred <= 0) {
    close(keycore_socket);
    return -1;
  }
  
  return byte_transferred;
}

static ssize_t
ethernet_read(uint8_t *buffer, uint16_t len)
{
  return recv(keycore_socket, &buffer[0], len);
}

keycore_handle_t keycore = {
  .initfn = ethernet_init,
  .readfn = ethernet_read,
  .writefn = ethernet_write,
};





