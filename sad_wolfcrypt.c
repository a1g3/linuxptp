
/**
 * @file sad_wolfcrypt.c
 * @brief Security Association Database wolfcrypt functions
 * @note Copyright (C) 2025 Alex Gebhard <alexander.gebhard@marquette.edu>
 * @note SPDX-License-Identifier: GPL-2.0+
 */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "print.h"
#include "sad.h"
#include "sad_private.h"

#define MAX_HEX_OUTPUT_LEN 1024
#define MAX_KEY_LEN 1024


void print_hex_array(const unsigned char *arr, size_t len) {
    if (!arr || len == 0 || len * 2 + 1 > MAX_HEX_OUTPUT_LEN) {
        pr_err("Invalid input to print_hex_array");
        return;
    }

    char output[(len * 2) + 1];
    char *ptr = output;

    for (size_t i = 0; i < len; i++) {
        ptr += sprintf(ptr, "%02X", arr[i]);
    }

    *ptr = '\0';
    pr_err("%s", output);
}

struct mac_data *sad_init_mac(integrity_alg_type algorithm,
                              const unsigned char *key1, const unsigned char *key2,
                              size_t key1_len, size_t key2_len)
{
    if (!key1 || key1_len == 0 || key1_len > MAX_KEY_LEN) {
        pr_err("Invalid key or key length");
        return NULL;
    }

    if (wolfCrypt_Init() != 0) {
        pr_err("wolfCrypt initialization failed");
        return NULL;
    }

    struct mac_data *mac_data = calloc(1, sizeof(*mac_data));
    if (!mac_data) {
        pr_err("Memory allocation for mac_data failed");
        wolfCrypt_Cleanup();
        return NULL;
    }

    switch (algorithm) {
        case HMAC_SHA256_128:
        case HMAC_SHA256:
            mac_data->wolfssl.hmac = calloc(1, sizeof(Hmac));
            if (!mac_data->wolfssl.hmac) {
                pr_err("Memory allocation for HMAC failed");
                free(mac_data);
                wolfCrypt_Cleanup();
                return NULL;
            }
            if (wc_HmacSetKey(mac_data->wolfssl.hmac, SHA256, key1, (word32)key1_len) != 0) {
                pr_err("Failed to set HMAC key");
                sad_deinit_mac(mac_data);
                return NULL;
            }
            mac_data->type = WC_HMAC;
            break;
	    case CMAC_AES128:
        case CMAC_AES256:
            mac_data->wolfssl.cmac = calloc(1, sizeof(Cmac));
            if (!mac_data->wolfssl.cmac) {
                pr_err("Memory allocation for CMAC failed");
                free(mac_data);
                wolfCrypt_Cleanup();
                return NULL;
            }
            if (wc_InitCmac(mac_data->wolfssl.cmac, key1, key1_len, 1, NULL) != 0) {
                pr_err("Failed to set CMAC key");
                sad_deinit_mac(mac_data);
                return NULL;
            }
            
            if (key1_len <= MAX_KEY_LEN) {
                memcpy(mac_data->key, key1, key1_len);
            } else {
                return NULL;
            }
            mac_data->type = WC_CMAC;
            mac_data->key_len = key1_len;
            break;

        case ED25519:
            int ret;

            mac_data->wolfssl.ed25519_key = calloc(1, sizeof(ed25519_key));
            if (!mac_data->wolfssl.ed25519_key) {
                pr_err("Memory allocation for ED25519 key failed");
                free(mac_data);
                wolfCrypt_Cleanup();
                return NULL;
            }

            if (!key2 || key2_len == 0 || key2_len > MAX_KEY_LEN) {
                pr_err("Invalid key or key length");
                return NULL;
            }

            //byte priv[] = { 0x61, 0xF0, 0xFE, 0x64, 0x7C, 0xDA, 0xDD, 0x61, 0xB2, 0x24, 0x78, 0x57, 0x78, 0x07, 0x12, 0xAB, 0x69, 0xE7, 0xB5, 0x9D, 0x0B, 0xEE, 0x43, 0xF9, 0x23, 0x33, 0x4F, 0xE5, 0xC7, 0x55, 0x57, 0x0E };
            //byte pub[]  = { 0x98, 0x18, 0x30, 0xA5, 0xF7, 0x70, 0xE5, 0xCD, 0x75, 0xE7, 0x3F, 0xC8, 0x92, 0xBF, 0x5A, 0xD3, 0x2B, 0xFA, 0x5F, 0xF2, 0x96, 0x7E, 0x9E, 0x26, 0x98, 0x54, 0x19, 0x27, 0xEC, 0x39, 0xBF, 0x93 };

            wc_ed25519_init(mac_data->wolfssl.ed25519_key);
            ret = wc_ed25519_import_private_key(key2, key2_len, key1, key2_len, mac_data->wolfssl.ed25519_key);
            if (ret != 0) {
                pr_err("Failed to import ED25519 key");
                sad_deinit_mac(mac_data);
                return NULL;
            }            

            mac_data->key_len = key1_len;
            mac_data->type = WC_ED25519;
            break;
        default:
            pr_err("Unknown integrity algorithm");
            sad_deinit_mac(mac_data);
            return NULL;
    }

    return mac_data;
}

void sad_deinit_mac(struct mac_data *mac_data)
{
    if (!mac_data)
        return;

    if (mac_data->type == WC_HMAC && mac_data->wolfssl.hmac) {
        free(mac_data->wolfssl.hmac);
        mac_data->wolfssl.hmac = NULL;
    }

    if (mac_data->type == WC_CMAC && mac_data->wolfssl.cmac) {
        free(mac_data->wolfssl.cmac);
        mac_data->wolfssl.cmac = NULL;
    }

    if (mac_data->type == WC_ED25519 && mac_data->wolfssl.ed25519_key) {
        free(mac_data->wolfssl.ed25519_key);
        mac_data->wolfssl.ed25519_key = NULL;
    }

    free(mac_data);
    wolfCrypt_Cleanup();
}

int sad_hash(struct mac_data *mac_data,
             const void *data, size_t data_len,
             unsigned char *mac, size_t mac_len)
{
    if (!mac_data || !data || !mac || data_len == 0 || mac_len == 0) {
        pr_err("Invalid input to sad_hash");
        return 0;
    }

    if (mac_data->type == WC_CMAC) {
        if (mac_len > AES_BLOCK_SIZE || mac_len > MAX_DIGEST_LENGTH) {
            pr_err("mac_len exceeds CMAC size");
            return 0;
        }

	    int ret = 0;
        if ( (ret = wc_CmacUpdate(mac_data->wolfssl.cmac, data, (word32)data_len)) != 0) {
            
	    pr_err("CMAC update failed with code 0x%08X", ret);
            return 0;
        }

        if (wc_CmacFinal(mac_data->wolfssl.cmac, mac, (unsigned int *)&mac_len) != 0) {
            pr_err("CMAC finalization failed");
            return 0;
        }

        if (wc_InitCmac(mac_data->wolfssl.cmac, mac_data->key, mac_data->key_len, WC_CMAC_AES, NULL) != 0) {
            pr_err("CMAC initialization failed");
                return 0;
        }

        return mac_len;
    } else if (mac_data->type == WC_ED25519) {
        if (mac_len > ED25519_SIG_SIZE) {
            pr_err("mac_len exceeds ED25519 signature size");
            return 0;
        }

        if (wc_ed25519_sign_msg(data, data_len, mac, (unsigned int *)&mac_len, mac_data->wolfssl.ed25519_key) != 0) {
            pr_err("ED25519 signing failed");
            return 0;
        }

        return mac_len;
    } else {
        const size_t digest_len = SHA256_DIGEST_SIZE;
        if (mac_len > digest_len || mac_len > MAX_DIGEST_LENGTH) {
            pr_err("mac_len exceeds HMAC size");
            return 0;
        }

        if (wc_HmacUpdate(mac_data->wolfssl.hmac, data, (word32)data_len) != 0) {
            pr_err("HMAC update failed");
            return 0;
        }

        if (wc_HmacFinal(mac_data->wolfssl.hmac, mac) != 0) {
            pr_err("HMAC finalization failed");
            return 0;
        }

        return mac_len;
    }
}

int sad_verify(struct mac_data *mac_data,
               const void *data, size_t data_len,
               unsigned char *mac, size_t mac_len)
{
    unsigned char digest_buf[MAX_DIGEST_LENGTH];
    int ret = 0;

    if (!mac || mac_len == 0) {
        pr_err("Invalid MAC input to sad_verify");
        return -1;
    }

    if (mac_data->type != WC_ED25519) {
        if (!sad_hash(mac_data, data, data_len, digest_buf, mac_len)) {
            pr_err("Failed to compute hash for verification");
            return -1;
        }

        return XMEMCMP(digest_buf, mac, mac_len);
    } else {
        if (wc_ed25519_verify_msg(mac, mac_len, data, data_len, &ret, mac_data->wolfssl.ed25519_key) != 0) {
            pr_err("ED25519 verification failed");
            return -1;
        }
        return !ret; // Signature is valid
    }
}

