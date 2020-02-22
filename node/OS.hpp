/*
 * Copyright (c)2013-2020 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2024-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
/****/

#ifndef ZT_OS_HPP
#define ZT_OS_HPP

//
// This include file also auto-detects and canonicalizes some environment
// information defines:
//
// __LINUX__
// __APPLE__
// __BSD__ (OSX also defines this)
// __UNIX_LIKE__ (Linux, BSD, etc.)
// __WINDOWS__
//
// Also makes sure __BYTE_ORDER is defined reasonably.
//

#ifndef __GCC__
#if defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_1) || defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_2) || defined(__GCC_HAVE_SYNC_COMPARE_AND_SWAP_4) || defined(__INTEL_COMPILER) || defined(__clang__)
#define __GCC__
#endif
#endif
#if defined(__GCC__) && !defined(__GNUC__)
#define __GNUC__
#endif

#if defined(__SIZEOF_INT128__) || ((defined(__GCC__) || defined(__GNUC__) || defined(__clang)) && (defined(__amd64) || defined(__amd64__) || defined(__x86_64) || defined(__x86_64__) || defined(__AMD64) || defined(__AMD64__) || defined(_M_X64) || defined(__aarch64__)))
#if defined(__SIZEOF_INT128__)
#define ZT_HAVE_UINT128 1
typedef unsigned __int128 uint128_t;
#else
#define ZT_HAVE_UINT128 1
typedef unsigned uint128_t __attribute__((mode(TI)));
#endif
#endif

#if (defined(__amd64) || defined(__amd64__) || defined(__x86_64) || defined(__x86_64__) || defined(__AMD64) || defined(__AMD64__) || defined(_M_X64))
#define ZT_ARCH_X64 1
#endif

// As far as we know it's only generally safe to do unaligned type casts in all
// cases on x86 and x64 architectures. Others such as ARM and MIPS will generate
// a fault or exhibit undefined behavior that varies by vendor.
#if (!(defined(ZT_ARCH_X64) || defined(i386) || defined(__i386) || defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__) || defined(_M_IX86) || defined(__X86__) || defined(_X86_) || defined(__I86__) || defined(__INTEL__) || defined(__386)))
#ifndef ZT_NO_UNALIGNED_ACCESS
#define ZT_NO_UNALIGNED_ACCESS 1
#endif
#endif

#if defined(_WIN32) || defined(_WIN64)
#ifdef _MSC_VER
#pragma warning(disable : 4290)
#pragma warning(disable : 4996)
#pragma warning(disable : 4101)
#endif
#ifndef __WINDOWS__
#define __WINDOWS__ 1
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#undef __UNIX_LIKE__
#undef __BSD__
#include <WinSock2.h>
#include <Windows.h>
#endif

#if defined(__linux__) || defined(linux) || defined(__LINUX__) || defined(__linux)
#ifndef __LINUX__
#define __LINUX__ 1
#endif
#ifndef __UNIX_LIKE__
#define __UNIX_LIKE__ 1
#endif
#include <endian.h>
#endif

#ifdef __APPLE__
#include <TargetConditionals.h>
#ifndef __UNIX_LIKE__
#define __UNIX_LIKE__ 1
#endif
#ifndef __BSD__
#define __BSD__ 1
#endif
#include <machine/endian.h>
#ifndef __BYTE_ORDER
#define __BYTE_ORDER __DARWIN_BYTE_ORDER
#define __BIG_ENDIAN __DARWIN_BIG_ENDIAN
#define __LITTLE_ENDIAN __DARWIN_LITTLE_ENDIAN
#endif
#endif

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#ifndef __UNIX_LIKE__
#define __UNIX_LIKE__ 1
#endif
#ifndef __BSD__
#define __BSD__ 1
#endif
#include <sys/endian.h>
#ifndef RTF_MULTICAST
#define RTF_MULTICAST 0x20000000
#endif
#endif

// It would probably be safe to assume LE everywhere except on very specific architectures as there
// are few BE chips remaining in the wild that are powerful enough to run this, but for now we'll
// try to include endian.h and error out if it doesn't exist.
#ifndef __BYTE_ORDER
#ifdef _BYTE_ORDER
#define __BYTE_ORDER _BYTE_ORDER
#define __LITTLE_ENDIAN _LITTLE_ENDIAN
#define __BIG_ENDIAN _BIG_ENDIAN
#else
#include <endian.h>
#endif
#endif

#if (defined(__GNUC__) && (__GNUC__ >= 3)) || (defined(__INTEL_COMPILER) && (__INTEL_COMPILER >= 800)) || defined(__clang__)
#ifdef ZT_DEBUG
#define ZT_ALWAYS_INLINE
#else
#define ZT_ALWAYS_INLINE __attribute__((always_inline)) inline
#endif
#ifndef restrict
#define restrict __restrict__
#endif
#ifndef likely
#define likely(x) __builtin_expect((x),1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect((x),0)
#endif
#else /* not GCC-like */
#ifndef restrict
#define restrict
#endif
#ifndef likely
#define likely(x) (x)
#endif
#ifndef unlikely
#define unlikely(x) (x)
#endif
#endif

#if __cplusplus > 199711L
#include <atomic>
#ifndef __CPP11__
#define __CPP11__
#endif
#endif
#ifndef __CPP11__
// TODO: we'll need to "polyfill" a subset of std::atomic for integers if we want to build on pre-C++11 compilers.
// Beyond that defining nullptr, constexpr, and noexcept should allow us to still build on these. So far we've
// avoided deeper C++11 features like lambdas in the core until we're 100% sure all the ancient targets are gone.
#error need pre-c++11 std::atomic implementation
#define nullptr (0)
#define constexpr ZT_ALWAYS_INLINE
#define noexcept throw()
#endif

#ifdef SOCKET
#define ZT_SOCKET SOCKET
#else
#define ZT_SOCKET int
#endif
#ifdef INVALID_SOCKET
#define ZT_INVALID_SOCKET INVALID_SOCKET
#else
#define ZT_INVALID_SOCKET -1
#endif

#ifdef __WINDOWS__
#define ZT_PATH_SEPARATOR '\\'
#define ZT_PATH_SEPARATOR_S "\\"
#define ZT_EOL_S "\r\n"
#else
#define ZT_PATH_SEPARATOR '/'
#define ZT_PATH_SEPARATOR_S "/"
#define ZT_EOL_S "\n"
#endif

#ifndef ZT_ALWAYS_INLINE
#ifdef ZT_DEBUG
#define ZT_ALWAYS_INLINE
#else
#define ZT_ALWAYS_INLINE inline
#endif
#endif

// Macro to avoid calling hton() on values known at compile time.
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ZT_CONST_TO_BE_UINT16(x) ((uint16_t)((uint16_t)((uint16_t)(x) << 8U) | (uint16_t)((uint16_t)(x) >> 8U)))
#else
#define ZT_CONST_TO_BE_UINT16(x) ((uint16_t)(x))
#endif

#endif
