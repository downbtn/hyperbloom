/**
 * @file crypto.h
 * @author Daniel Ha
 * @brief 
 * @date 2025
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */
#pragma once

#include "wolfssl/wolfcrypt/hmac.h"
#include "wolfssl/wolfcrypt/aes.h"
#include <stdint.h>

void compute_hmac(const uint8_t* buf, uint32_t len, const uint8_t* key, uint8_t* out);
void decrypt_sym(const uint8_t *ciphertext, uint32_t len, const uint8_t *iv, const uint8_t *key, uint8_t *out);
