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

#ifndef ZT_MUTEX_HPP
#define ZT_MUTEX_HPP

#include "Constants.hpp"

#ifdef __UNIX_LIKE__

#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>

namespace ZeroTier {

#if defined(__GNUC__) && (defined(__amd64) || defined(__amd64__) || defined(__x86_64) || defined(__x86_64__) || defined(__AMD64) || defined(__AMD64__) || defined(_M_X64))

// Inline ticket lock with yield for x64 systems, provides much better performance when there is no contention.
class Mutex
{
public:
	ZT_ALWAYS_INLINE Mutex() : nextTicket(0),nowServing(0) {}

	ZT_ALWAYS_INLINE void lock() const
	{
		const uint16_t myTicket = __sync_fetch_and_add(&(const_cast<Mutex *>(this)->nextTicket),1);
		while (nowServing != myTicket) {
			pthread_yield_np();
			__asm__ __volatile__("rep;nop"::);
			__asm__ __volatile__("":::"memory");
		}
	}

	ZT_ALWAYS_INLINE void unlock() const { ++(const_cast<Mutex *>(this)->nowServing); }

	class Lock
	{
	public:
		ZT_ALWAYS_INLINE Lock(Mutex &m) : _m(&m) { m.lock(); }
		ZT_ALWAYS_INLINE Lock(const Mutex &m) : _m(const_cast<Mutex *>(&m)) { _m->lock(); }
		ZT_ALWAYS_INLINE ~Lock() { _m->unlock(); }
	private:
		Mutex *const _m;
	};

private:
	inline Mutex(const Mutex &) {}
	const Mutex &operator=(const Mutex &) { return *this; }

	uint16_t nextTicket;
	uint16_t nowServing;
};

#else

// libpthread based mutex lock
class Mutex
{
public:
	ZT_ALWAYS_INLINE Mutex() { pthread_mutex_init(&_mh,(const pthread_mutexattr_t *)0); }
	ZT_ALWAYS_INLINE ~Mutex() { pthread_mutex_destroy(&_mh); }
	ZT_ALWAYS_INLINE void lock() const { pthread_mutex_lock(&((const_cast <Mutex *> (this))->_mh)); }
	ZT_ALWAYS_INLINE void unlock() const { pthread_mutex_unlock(&((const_cast <Mutex *> (this))->_mh)); }

	class Lock
	{
	public:
		ZT_ALWAYS_INLINE Lock(Mutex &m) : _m(&m) { m.lock(); }
		ZT_ALWAYS_INLINE Lock(const Mutex &m) : _m(const_cast<Mutex *>(&m)) { _m->lock(); }
		ZT_ALWAYS_INLINE ~Lock() { _m->unlock(); }
	private:
		Mutex *const _m;
	};

private:
	inline Mutex(const Mutex &) {}
	const Mutex &operator=(const Mutex &) { return *this; }

	pthread_mutex_t _mh;
};

#endif

} // namespace ZeroTier

#endif // Apple / Linux

#ifdef __WINDOWS__

#include <stdlib.h>
#include <Windows.h>

namespace ZeroTier {

// Windows critical section based lock
class Mutex
{
public:
	ZT_ALWAYS_INLINE Mutex() { InitializeCriticalSection(&_cs); }
	ZT_ALWAYS_INLINE ~Mutex() { DeleteCriticalSection(&_cs); }
	ZT_ALWAYS_INLINE void lock() { EnterCriticalSection(&_cs); }
	ZT_ALWAYS_INLINE void unlock() { LeaveCriticalSection(&_cs); }
	ZT_ALWAYS_INLINE void lock() const { (const_cast <Mutex *> (this))->lock(); }
	ZT_ALWAYS_INLINE void unlock() const { (const_cast <Mutex *> (this))->unlock(); }

	class Lock
	{
	public:
		ZT_ALWAYS_INLINE Lock(Mutex &m) : _m(&m) { m.lock(); }
		ZT_ALWAYS_INLINE Lock(const Mutex &m) : _m(const_cast<Mutex *>(&m)) { _m->lock(); }
		ZT_ALWAYS_INLINE ~Lock() { _m->unlock(); }
	private:
		Mutex *const _m;
	};

private:
	inline Mutex(const Mutex &) {}
	const Mutex &operator=(const Mutex &) { return *this; }

	CRITICAL_SECTION _cs;
};

} // namespace ZeroTier

#endif // _WIN32

#endif
