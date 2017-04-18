/*
 * Based on public domain code available at: http://cr.yp.to/snuffle.html
 *
 * This therefore is public domain.
 */

#ifndef ZT_SALSA20_HPP
#define ZT_SALSA20_HPP

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "Constants.hpp"
#include "Utils.hpp"

#if (!defined(ZT_SALSA20_SSE)) && (defined(__SSE2__) || defined(__WINDOWS__))
#define ZT_SALSA20_SSE 1
#endif

#ifdef ZT_SALSA20_SSE
#include <emmintrin.h>
#endif // ZT_SALSA20_SSE

namespace ZeroTier {

/**
 * Salsa20 stream cipher
 */
class Salsa20
{
public:
	Salsa20() {}
	~Salsa20() { Utils::burn(&_state,sizeof(_state)); }

	/**
	 * If this returns true, crypt can only be done once
	 */
	static inline bool singleUseOnly() { return false; }

	/**
	 * @param key 256-bit (32 byte) key
	 * @param iv 64-bit initialization vector
	 */
	Salsa20(const void *key,const void *iv)
	{
		init(key,iv);
	}

	/**
	 * Initialize cipher
	 *
	 * @param key Key bits
	 * @param iv 64-bit initialization vector
	 */
	void init(const void *key,const void *iv);

	/**
	 * Encrypt/decrypt data using Salsa20/12
	 *
	 * @param in Input data
	 * @param out Output buffer
	 * @param bytes Length of data
	 */
	void crypt12(const void *in,void *out,unsigned int bytes);

	/**
	 * Encrypt/decrypt data using Salsa20/20
	 *
	 * @param in Input data
	 * @param out Output buffer
	 * @param bytes Length of data
	 */
	void crypt20(const void *in,void *out,unsigned int bytes);

private:
	union {
#ifdef ZT_SALSA20_SSE
		__m128i v[4];
#endif // ZT_SALSA20_SSE
		uint32_t i[16];
	} _state;
};

} // namespace ZeroTier

#endif
