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

#ifndef ZT_UTILS_HPP
#define ZT_UTILS_HPP

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <ctime>

#if (defined(__amd64) || defined(__amd64__) || defined(__x86_64) || defined(__x86_64__) || defined(__AMD64) || defined(__AMD64__) || defined(_M_X64))
#include <emmintrin.h>
#include <xmmintrin.h>
#include <immintrin.h>
#endif

#include <string>
#include <stdexcept>
#include <vector>
#include <map>

#include "Constants.hpp"

namespace ZeroTier {

namespace Utils {

#if (defined(__amd64) || defined(__amd64__) || defined(__x86_64) || defined(__x86_64__) || defined(__AMD64) || defined(__AMD64__) || defined(_M_X64))
struct CPUIDRegisters
{
	uint32_t eax,ebx,ecx,edx;
	bool rdrand;
	bool aes;
	CPUIDRegisters();
};
extern CPUIDRegisters CPUID;
#endif

/**
 * Hexadecimal characters 0-f
 */
extern const char HEXCHARS[16];

/**
 * Perform a time-invariant binary comparison
 *
 * @param a First binary string
 * @param b Second binary string
 * @param len Length of strings
 * @return True if strings are equal
 */
bool secureEq(const void *a,const void *b,unsigned int len);

/**
 * Zero memory, ensuring to avoid any compiler optimizations or other things that may stop this.
 */
void burn(void *ptr,unsigned int len);

/**
 * @param n Number to convert
 * @param s Buffer, at least 24 bytes in size
 * @return String containing 'n' in base 10 form
 */
char *decimal(unsigned long n,char s[24]);

/**
 * Convert an unsigned integer into hex
 *
 * @param i Any unsigned integer
 * @param s Buffer to receive hex, must be at least (2*sizeof(i))+1 in size or overflow will occur.
 * @return Pointer to s containing hex string with trailing zero byte
 */
template<typename I>
static inline char *hex(I x,char *s)
{
	char *const r = s;
	for(unsigned int i=0,b=(sizeof(x)*8);i<sizeof(x);++i) {
		*(s++) = HEXCHARS[(x >> (b -= 4)) & 0xf];
		*(s++) = HEXCHARS[(x >> (b -= 4)) & 0xf];
	}
	*s = (char)0;
	return r;
}

/**
 * Convert the least significant 40 bits of a uint64_t to hex
 *
 * @param i Unsigned 64-bit int
 * @param s Buffer of size [11] to receive 10 hex characters
 * @return Pointer to buffer
 */
char *hex10(uint64_t i,char s[11]);

/**
 * Convert a byte array into hex
 *
 * @param d Bytes
 * @param l Length of bytes
 * @param s String buffer, must be at least (l*2)+1 in size or overflow will occur
 * @return Pointer to filled string buffer
 */
char *hex(const void *d,unsigned int l,char *s);

/**
 * Decode a hex string
 *
 * @param h Hex C-string (non hex chars are ignored)
 * @param hlen Maximum length of string (will stop at terminating zero)
 * @param buf Output buffer
 * @param buflen Length of output buffer
 * @return Number of written bytes
 */
unsigned int unhex(const char *h,unsigned int hlen,void *buf,unsigned int buflen);

/**
 * Generate secure random bytes
 *
 * This will try to use whatever OS sources of entropy are available. It's
 * guarded by an internal mutex so it's thread-safe.
 *
 * @param buf Buffer to fill
 * @param bytes Number of random bytes to generate
 */
void getSecureRandom(void *buf,unsigned int bytes);

/**
 * Encode string to base32
 *
 * @param data Binary data to encode
 * @param length Length of data in bytes
 * @param result Result buffer
 * @param bufSize Size of result buffer
 * @return Number of bytes written
 */
int b32e(const uint8_t *data,int length,char *result,int bufSize);

/**
 * Decode base32 string
 *
 * @param encoded C-string in base32 format (non-base32 characters are ignored)
 * @param result Result buffer
 * @param bufSize Size of result buffer
 * @return Number of bytes written or -1 on error
 */
int b32d(const char *encoded, uint8_t *result, int bufSize);

/**
 * Get a non-cryptographic random integer
 */
uint64_t random();

/**
 * Perform a safe C string copy, ALWAYS null-terminating the result
 *
 * This will never ever EVER result in dest[] not being null-terminated
 * regardless of any input parameter (other than len==0 which is invalid).
 *
 * @param dest Destination buffer (must not be NULL)
 * @param len Length of dest[] (if zero, false is returned and nothing happens)
 * @param src Source string (if NULL, dest will receive a zero-length string and true is returned)
 * @return True on success, false on overflow (buffer will still be 0-terminated)
 */
bool scopy(char *dest,unsigned int len,const char *src);

/**
 * Tokenize a string (alias for strtok_r or strtok_s depending on platform)
 *
 * @param str String to split
 * @param delim Delimiters
 * @param saveptr Pointer to a char * for temporary reentrant storage
 */
ZT_ALWAYS_INLINE char *stok(char *str,const char *delim,char **saveptr)
{
#ifdef __WINDOWS__
	return strtok_s(str,delim,saveptr);
#else
	return strtok_r(str,delim,saveptr);
#endif
}

ZT_ALWAYS_INLINE unsigned int strToUInt(const char *s) { return (unsigned int)strtoul(s,(char **)0,10); }
ZT_ALWAYS_INLINE int strToInt(const char *s) { return (int)strtol(s,(char **)0,10); }
ZT_ALWAYS_INLINE unsigned long strToULong(const char *s) { return strtoul(s,(char **)0,10); }
ZT_ALWAYS_INLINE long strToLong(const char *s) { return strtol(s,(char **)0,10); }
ZT_ALWAYS_INLINE unsigned long long strToU64(const char *s)
{
#ifdef __WINDOWS__
	return (unsigned long long)_strtoui64(s,(char **)0,10);
#else
	return strtoull(s,(char **)0,10);
#endif
}
ZT_ALWAYS_INLINE long long strTo64(const char *s)
{
#ifdef __WINDOWS__
	return (long long)_strtoi64(s,(char **)0,10);
#else
	return strtoll(s,(char **)0,10);
#endif
}
ZT_ALWAYS_INLINE unsigned int hexStrToUInt(const char *s) { return (unsigned int)strtoul(s,(char **)0,16); }
ZT_ALWAYS_INLINE int hexStrToInt(const char *s) { return (int)strtol(s,(char **)0,16); }
ZT_ALWAYS_INLINE unsigned long hexStrToULong(const char *s) { return strtoul(s,(char **)0,16); }
ZT_ALWAYS_INLINE long hexStrToLong(const char *s) { return strtol(s,(char **)0,16); }
ZT_ALWAYS_INLINE unsigned long long hexStrToU64(const char *s)
{
#ifdef __WINDOWS__
	return (unsigned long long)_strtoui64(s,(char **)0,16);
#else
	return strtoull(s,(char **)0,16);
#endif
}
ZT_ALWAYS_INLINE long long hexStrTo64(const char *s)
{
#ifdef __WINDOWS__
	return (long long)_strtoi64(s,(char **)0,16);
#else
	return strtoll(s,(char **)0,16);
#endif
}

/**
 * Calculate a non-cryptographic hash of a byte string
 *
 * @param key Key to hash
 * @param len Length in bytes
 * @return Non-cryptographic hash suitable for use in a hash table
 */
ZT_ALWAYS_INLINE unsigned long hashString(const void *restrict key,const unsigned int len)
{
	const uint8_t *p = reinterpret_cast<const uint8_t *>(key);
	unsigned long h = 0;
	for (unsigned int i=0;i<len;++i) {
		h += p[i];
		h += (h << 10);
		h ^= (h >> 6);
	}
	h += (h << 3);
	h ^= (h >> 11);
	h += (h << 15);
	return h;
}

#ifdef __GNUC__
ZT_ALWAYS_INLINE unsigned int countBits(const uint8_t v) { return (unsigned int)__builtin_popcount((unsigned int)v); }
ZT_ALWAYS_INLINE unsigned int countBits(const uint16_t v) { return (unsigned int)__builtin_popcount((unsigned int)v); }
ZT_ALWAYS_INLINE unsigned int countBits(const uint32_t v) { return (unsigned int)__builtin_popcountl((unsigned long)v); }
ZT_ALWAYS_INLINE unsigned int countBits(const uint64_t v) { return (unsigned int)__builtin_popcountll((unsigned long long)v); }
#else
template<typename T>
ZT_ALWAYS_INLINE unsigned int countBits(T v)
{
	v = v - ((v >> 1) & (T)~(T)0/3);
	v = (v & (T)~(T)0/15*3) + ((v >> 2) & (T)~(T)0/15*3);
	v = (v + (v >> 4)) & (T)~(T)0/255*15;
	return (unsigned int)((v * ((~((T)0))/((T)255))) >> ((sizeof(T) - 1) * 8));
}
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
ZT_ALWAYS_INLINE uint8_t hton(uint8_t n) { return n; }
ZT_ALWAYS_INLINE int8_t hton(int8_t n) { return n; }
ZT_ALWAYS_INLINE uint16_t hton(uint16_t n)
{
#if defined(__GNUC__)
#if defined(__FreeBSD__)
	return htons(n);
#elif (!defined(__OpenBSD__))
	return __builtin_bswap16(n);
#endif
#else
	return htons(n);
#endif
}
ZT_ALWAYS_INLINE int16_t hton(int16_t n) { return (int16_t)Utils::hton((uint16_t)n); }
ZT_ALWAYS_INLINE uint32_t hton(uint32_t n)
{
#if defined(__GNUC__)
#if defined(__FreeBSD__)
	return htonl(n);
#elif (!defined(__OpenBSD__))
	return __builtin_bswap32(n);
#endif
#else
	return htonl(n);
#endif
}
ZT_ALWAYS_INLINE int32_t hton(int32_t n) { return (int32_t)Utils::hton((uint32_t)n); }
ZT_ALWAYS_INLINE uint64_t hton(uint64_t n)
{
#if defined(__GNUC__)
#if defined(__FreeBSD__)
	return bswap64(n);
#elif (!defined(__OpenBSD__))
	return __builtin_bswap64(n);
#endif
#else
	return (
		((n & 0x00000000000000FFULL) << 56) |
		((n & 0x000000000000FF00ULL) << 40) |
		((n & 0x0000000000FF0000ULL) << 24) |
		((n & 0x00000000FF000000ULL) <<  8) |
		((n & 0x000000FF00000000ULL) >>  8) |
		((n & 0x0000FF0000000000ULL) >> 24) |
		((n & 0x00FF000000000000ULL) >> 40) |
		((n & 0xFF00000000000000ULL) >> 56)
	);
#endif
}
ZT_ALWAYS_INLINE int64_t hton(int64_t n) { return (int64_t)hton((uint64_t)n); }
#else
template<typename T>
static ZT_ALWAYS_INLINE T hton(T n) { return n; }
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
ZT_ALWAYS_INLINE uint8_t ntoh(uint8_t n) { return n; }
ZT_ALWAYS_INLINE int8_t ntoh(int8_t n) { return n; }
ZT_ALWAYS_INLINE uint16_t ntoh(uint16_t n)
{
#if defined(__GNUC__)
#if defined(__FreeBSD__)
	return htons(n);
#elif (!defined(__OpenBSD__))
	return __builtin_bswap16(n);
#endif
#else
	return htons(n);
#endif
}
ZT_ALWAYS_INLINE int16_t ntoh(int16_t n) { return (int16_t)Utils::ntoh((uint16_t)n); }
ZT_ALWAYS_INLINE uint32_t ntoh(uint32_t n)
{
#if defined(__GNUC__)
#if defined(__FreeBSD__)
	return ntohl(n);
#elif (!defined(__OpenBSD__))
	return __builtin_bswap32(n);
#endif
#else
	return ntohl(n);
#endif
}
ZT_ALWAYS_INLINE int32_t ntoh(int32_t n) { return (int32_t)Utils::ntoh((uint32_t)n); }
ZT_ALWAYS_INLINE uint64_t ntoh(uint64_t n)
{
#if defined(__GNUC__)
#if defined(__FreeBSD__)
	return bswap64(n);
#elif (!defined(__OpenBSD__))
	return __builtin_bswap64(n);
#endif
#else
	return (
		((n & 0x00000000000000FFULL) << 56) |
		((n & 0x000000000000FF00ULL) << 40) |
		((n & 0x0000000000FF0000ULL) << 24) |
		((n & 0x00000000FF000000ULL) <<  8) |
		((n & 0x000000FF00000000ULL) >>  8) |
		((n & 0x0000FF0000000000ULL) >> 24) |
		((n & 0x00FF000000000000ULL) >> 40) |
		((n & 0xFF00000000000000ULL) >> 56)
	);
#endif
}
ZT_ALWAYS_INLINE int64_t ntoh(int64_t n) { return (int64_t)ntoh((uint64_t)n); }
#else
template<typename T>
ZT_ALWAYS_INLINE T ntoh(T n) { return n; }
#endif

ZT_ALWAYS_INLINE uint64_t readUInt64(const void *const p)
{
#ifdef ZT_NO_TYPE_PUNNING
	const uint8_t *const b = reinterpret_cast<const uint8_t *>(p);
	return (
		((uint64_t)b[0] << 56) |
		((uint64_t)b[1] << 48) |
		((uint64_t)b[2] << 40) |
		((uint64_t)b[3] << 32) |
		((uint64_t)b[4] << 24) |
		((uint64_t)b[5] << 16) |
		((uint64_t)b[6] << 8) |
		(uint64_t)b[7]);
#else
	return ntoh(*reinterpret_cast<const uint64_t *>(p));
#endif
}

ZT_ALWAYS_INLINE void putUInt64(void *const p,const uint64_t i)
{
#ifdef ZT_NO_TYPE_PUNNING
	uint8_t *const b = reinterpret_cast<uint8_t *>(p);
	p[0] = (uint8_t)(i << 56);
	p[1] = (uint8_t)(i << 48);
	p[2] = (uint8_t)(i << 40);
	p[3] = (uint8_t)(i << 32);
	p[4] = (uint8_t)(i << 24);
	p[5] = (uint8_t)(i << 16);
	p[6] = (uint8_t)(i << 8);
	p[7] = (uint8_t)i;
#else
	*reinterpret_cast<uint64_t *>(p) = Utils::hton(i);
#endif
}

} // namespace Utils

} // namespace ZeroTier

#endif
