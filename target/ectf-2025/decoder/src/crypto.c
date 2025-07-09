#include "crypto.h"

void compute_hmac(const uint8_t *buf, uint32_t len, const uint8_t *key,
                  uint8_t *out)
{
    Hmac hmac;

    wc_HmacSetKey(&hmac, WC_SHA256, key, 32);
    wc_HmacUpdate(&hmac, buf, len);
    wc_HmacFinal(&hmac, out);
}

void decrypt_sym(const uint8_t *ciphertext, uint32_t len, const uint8_t *iv,
                 const uint8_t *key, uint8_t *out)
{
    Aes aes;

    wc_AesInit(&aes, NULL, INVALID_DEVID);
    wc_AesSetKeyDirect(&aes, key, 32, iv, AES_ENCRYPTION);

    wc_AesCtrEncrypt(&aes, out, ciphertext, len);
    wc_AesFree(&aes);
}
