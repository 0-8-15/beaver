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

#include "Buf.hpp"

namespace ZeroTier {

#ifdef __GNUC__
uintptr_t _Buf_pool = 0;
#else
std::atomic<uintptr_t> _Buf_pool(0);
#endif

void _Buf_release(void *ptr,std::size_t sz)
{
	if (ptr) {
		uintptr_t bb;
		const uintptr_t locked = ~((uintptr_t)0);
		for (;;) {
#ifdef __GNUC__
			bb = __sync_fetch_and_or(&_Buf_pool,locked); // get value of s_pool and "lock" by filling with all 1's
#else
			bb = s_pool.fetch_or(locked);
#endif
			if (bb != locked)
				break;
		}

		((Buf<> *)ptr)->__nextInPool = bb;
#ifdef __GNUC__
		__sync_fetch_and_and(&_Buf_pool,(uintptr_t)ptr);
#else
		s_pool.store((uintptr_t)ptr);
#endif
	}
}

void *_Buf_get()
{
	uintptr_t bb;
	const uintptr_t locked = ~((uintptr_t)0);
	for (;;) {
#ifdef __GNUC__
		bb = __sync_fetch_and_or(&_Buf_pool,locked); // get value of s_pool and "lock" by filling with all 1's
#else
		bb = s_pool.fetch_or(locked);
#endif
		if (bb != locked)
			break;
	}

	Buf<> *b;
	if (bb == 0) {
#ifdef __GNUC__
		__sync_fetch_and_and(&_Buf_pool,bb);
#else
		s_pool.store(bb);
#endif
		b = (Buf<> *)malloc(sizeof(Buf<>));
		if (!b)
			return nullptr;
	} else {
		b = (Buf<> *)bb;
#ifdef __GNUC__
		__sync_fetch_and_and(&_Buf_pool,b->__nextInPool);
#else
		s_pool.store(b->__nextInPool);
#endif
	}

	b->__refCount.zero();
	return (void *)b;
}

void freeBufPool()
{
	uintptr_t bb;
	const uintptr_t locked = ~((uintptr_t)0);
	for (;;) {
#ifdef __GNUC__
		bb = __sync_fetch_and_or(&_Buf_pool,locked); // get value of s_pool and "lock" by filling with all 1's
#else
		bb = s_pool.fetch_or(locked);
#endif
		if (bb != locked)
			break;
	}

#ifdef __GNUC__
	__sync_fetch_and_and(&_Buf_pool,(uintptr_t)0);
#else
	s_pool.store((uintptr_t)0);
#endif

	while (bb != 0) {
		uintptr_t next = ((Buf<> *)bb)->__nextInPool;
		free((void *)bb);
		bb = next;
	}
}

} // namespace ZeroTier
