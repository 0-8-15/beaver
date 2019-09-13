/*
 * Copyright (c)2019 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2023-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
/****/

#if (defined(__amd64) || defined(__amd64__) || defined(__x86_64) || defined(__x86_64__) || defined(__AMD64) || defined(__AMD64__) || defined(_M_X64))

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#include <immintrin.h>

/* #define register */

void zt_crypt_ctr_aesni(const __m128i key[14],const uint8_t iv[16],const uint8_t *in,unsigned int len,uint8_t *out)
{
	_mm_prefetch(in,_MM_HINT_NTA);

	/* Because our CTR supports full 128-bit nonces, we must do a full 128-bit (big-endian)
	 * increment to be compatible with canonical NIST-certified CTR implementations. That's
	 * because it's possible to have a lot of bit saturation in the least significant 64
	 * bits, which could on rare occasions actually cause a 64-bit wrap. If this happened
	 * without carry it would result in incompatibility and quietly dropped packets. The
	 * probability is low, so this would be a one in billions packet loss bug that would
	 * probably never be found.
	 *
	 * This crazy code does a branch-free 128-bit increment by adding a one or a zero to
	 * the most significant 64 bits of the 128-bit vector based on whether the add we want
	 * to do to the least significant 64 bits would overflow. This can be computed by
	 * NOTing those bits and comparing with what we want to add, since NOT is the same
	 * as subtracting from uint64_max. This generates branch-free ASM on x64 with most
	 * good compilers. */
	register __m128i swap128 = _mm_set_epi8(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
	register __m128i ctr0 = _mm_shuffle_epi8(_mm_loadu_si128((__m128i *)iv),swap128);
	register uint64_t notctr0msq = ~((uint64_t)_mm_extract_epi64(ctr0,0));
	register __m128i ctr1 = _mm_shuffle_epi8(_mm_add_epi64(ctr0,_mm_set_epi64x((long long)(notctr0msq < 1ULL),1LL)),swap128);
	register __m128i ctr2 = _mm_shuffle_epi8(_mm_add_epi64(ctr0,_mm_set_epi64x((long long)(notctr0msq < 2ULL),2LL)),swap128);
	register __m128i ctr3 = _mm_shuffle_epi8(_mm_add_epi64(ctr0,_mm_set_epi64x((long long)(notctr0msq < 3ULL),3LL)),swap128);
	ctr0 = _mm_shuffle_epi8(ctr0,swap128);

	while (len >= 64) {
		_mm_prefetch(in + 64,_MM_HINT_NTA);
		register __m128i ka = key[0];
		register __m128i c0 = _mm_xor_si128(ctr0,ka);
		ctr0 = _mm_shuffle_epi8(ctr0,swap128);
		notctr0msq = ~((uint64_t)_mm_extract_epi64(ctr0,0));
		register __m128i c1 = _mm_xor_si128(ctr1,ka);
		register __m128i c2 = _mm_xor_si128(ctr2,ka);
		register __m128i c3 = _mm_xor_si128(ctr3,ka);
		register __m128i kb = key[1];
		ctr1 = _mm_shuffle_epi8(_mm_add_epi64(ctr0,_mm_set_epi64x((long long)(notctr0msq < 5ULL),5LL)),swap128);
		ctr2 = _mm_shuffle_epi8(_mm_add_epi64(ctr0,_mm_set_epi64x((long long)(notctr0msq < 6ULL),6LL)),swap128);
		register __m128i kc = key[2];
		ctr3 = _mm_shuffle_epi8(_mm_add_epi64(ctr0,_mm_set_epi64x((long long)(notctr0msq < 7ULL),7LL)),swap128);
		ctr0 = _mm_shuffle_epi8(_mm_add_epi64(ctr0,_mm_set_epi64x((long long)(notctr0msq < 4ULL),4LL)),swap128);
		register __m128i kd = key[3];
#define ZT_AES_CTR_AESNI_ROUND(kk) \
		c0 = _mm_aesenc_si128(c0,kk);  \
		c1 = _mm_aesenc_si128(c1,kk);  \
		c2 = _mm_aesenc_si128(c2,kk);  \
		c3 = _mm_aesenc_si128(c3,kk);
		ka = key[4];
		ZT_AES_CTR_AESNI_ROUND(kb);
		kb = key[5];
		ZT_AES_CTR_AESNI_ROUND(kc);
		kc = key[6];
		ZT_AES_CTR_AESNI_ROUND(kd);
		kd = key[7];
		ZT_AES_CTR_AESNI_ROUND(ka);
		ka = key[8];
		ZT_AES_CTR_AESNI_ROUND(kb);
		kb = key[9];
		ZT_AES_CTR_AESNI_ROUND(kc);
		kc = key[10];
		ZT_AES_CTR_AESNI_ROUND(kd);
		kd = key[11];
		ZT_AES_CTR_AESNI_ROUND(ka);
		ka = key[12];
		ZT_AES_CTR_AESNI_ROUND(kb);
		kb = key[13];
		ZT_AES_CTR_AESNI_ROUND(kc);
		kc = key[14];
		ZT_AES_CTR_AESNI_ROUND(kd);
		ZT_AES_CTR_AESNI_ROUND(ka);
		ZT_AES_CTR_AESNI_ROUND(kb);
#undef ZT_AES_CTR_AESNI_ROUND
		register __m128i d0 = _mm_loadu_si128((const __m128i *)in);
		register __m128i d1 = _mm_loadu_si128((const __m128i *)(in + 16));
		register __m128i d2 = _mm_loadu_si128((const __m128i *)(in + 32));
		register __m128i d3 = _mm_loadu_si128((const __m128i *)(in + 48));
		c0 = _mm_aesenclast_si128(c0,kc);
		c1 = _mm_aesenclast_si128(c1,kc);
		c2 = _mm_aesenclast_si128(c2,kc);
		c3 = _mm_aesenclast_si128(c3,kc);
		d0 = _mm_xor_si128(d0,c0);
		d1 = _mm_xor_si128(d1,c1);
		d2 = _mm_xor_si128(d2,c2);
		d3 = _mm_xor_si128(d3,c3);
		_mm_storeu_si128((__m128i *)out,d0);
		_mm_storeu_si128((__m128i *)(out + 16),d1);
		_mm_storeu_si128((__m128i *)(out + 32),d2);
		_mm_storeu_si128((__m128i *)(out + 48),d3);
		in += 64;
		out += 64;
		len -= 64;
	}

	register __m128i k0 = key[0];
	register __m128i k1 = key[1];
	register __m128i k2 = key[2];
	register __m128i k3 = key[3];
	register __m128i k4 = key[4];
	register __m128i k5 = key[5];
	register __m128i k6 = key[6];
	register __m128i k7 = key[7];
	/* not enough XMM registers for all of them, but it helps slightly... */

	while (len >= 16) {
		register __m128i c0 = _mm_xor_si128(ctr0,k0);
		ctr0 = _mm_shuffle_epi8(ctr0,swap128);
		ctr0 = _mm_shuffle_epi8(_mm_add_epi64(ctr0,_mm_set_epi64x((long long)((~((uint64_t)_mm_extract_epi64(ctr0,0))) < 1ULL),1LL)),swap128);
		c0 = _mm_aesenc_si128(c0,k1);
		c0 = _mm_aesenc_si128(c0,k2);
		c0 = _mm_aesenc_si128(c0,k3);
		c0 = _mm_aesenc_si128(c0,k4);
		c0 = _mm_aesenc_si128(c0,k5);
		c0 = _mm_aesenc_si128(c0,k6);
		register __m128i ka = key[8];
		c0 = _mm_aesenc_si128(c0,k7);
		register __m128i kb = key[9];
		c0 = _mm_aesenc_si128(c0,ka);
		ka = key[10];
		c0 = _mm_aesenc_si128(c0,kb);
		kb = key[11];
		c0 = _mm_aesenc_si128(c0,ka);
		ka = key[12];
		c0 = _mm_aesenc_si128(c0,kb);
		kb = key[13];
		c0 = _mm_aesenc_si128(c0,ka);
		ka = key[14];
		c0 = _mm_aesenc_si128(c0,kb);
		_mm_storeu_si128((__m128i *)out,_mm_xor_si128(_mm_loadu_si128((const __m128i *)in),_mm_aesenclast_si128(c0,ka)));
		in += 16;
		out += 16;
		len -= 16;
	}

	if (len) {
		register __m128i c0 = _mm_xor_si128(ctr0,k0);
		k0 = key[8];
		c0 = _mm_aesenc_si128(c0,k1);
		c0 = _mm_aesenc_si128(c0,k2);
		k1 = key[9];
		c0 = _mm_aesenc_si128(c0,k3);
		c0 = _mm_aesenc_si128(c0,k4);
		k2 = key[10];
		c0 = _mm_aesenc_si128(c0,k5);
		c0 = _mm_aesenc_si128(c0,k6);
		k3 = key[11];
		c0 = _mm_aesenc_si128(c0,k7);
		c0 = _mm_aesenc_si128(c0,k0);
		k0 = key[12];
		c0 = _mm_aesenc_si128(c0,k1);
		c0 = _mm_aesenc_si128(c0,k2);
		k1 = key[13];
		c0 = _mm_aesenc_si128(c0,k3);
		c0 = _mm_aesenc_si128(c0,k0);
		k2 = key[14];
		c0 = _mm_aesenc_si128(c0,k1);
		c0 = _mm_aesenclast_si128(c0,k2);
		uint8_t tmp[16];
		_mm_storeu_si128((__m128i *)tmp,c0);
		for(unsigned int i=0;i<len;++i)
			out[i] = in[i] ^ tmp[i];
	}
}

#endif
