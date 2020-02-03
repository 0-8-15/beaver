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

#ifndef ZT_TRIVIALLYCOPYABLE_HPP
#define ZT_TRIVIALLYCOPYABLE_HPP

#include "Constants.hpp"
#include "Utils.hpp"

#include <cstring>
#include <cstdlib>

namespace ZeroTier {

/**
 * This is a class that others can inherit from to tag themselves as safe to abuse in C-like ways with memcpy, etc.
 *
 * Later versions of C++ have a built-in auto-detected notion like this, but
 * this is more explicit and its use will make audits for memory safety
 * a lot easier.
 */
class TriviallyCopyable
{
public:
	/**
	 * Be absolutely sure a TriviallyCopyable object is zeroed using Utils::burn()
	 *
	 * @tparam T Automatically inferred type of object
	 * @param obj Any TriviallyCopyable object
	 */
	template<typename T>
	static ZT_ALWAYS_INLINE void memoryBurn(T *obj)
	{
		TriviallyCopyable *const tmp = obj;
		Utils::burn(tmp,sizeof(T));
	}

	/**
	 * Be absolutely sure a TriviallyCopyable object is zeroed using Utils::burn()
	 *
	 * @tparam T Automatically inferred type of object
	 * @param obj Any TriviallyCopyable object
	 */
	template<typename T>
	static ZT_ALWAYS_INLINE void memoryBurn(T &obj)
	{
		TriviallyCopyable *const tmp = &obj;
		Utils::burn(tmp,sizeof(T));
	}

	/**
	 * Zero a TriviallyCopyable object
	 *
	 * @tparam T Automatically inferred type of object
	 * @param obj Any TriviallyCopyable object
	 */
	template<typename T>
	static ZT_ALWAYS_INLINE void memoryZero(T *obj)
	{
		TriviallyCopyable *const tmp = obj;
		memset(tmp,0,sizeof(T));
	}

	/**
	 * Zero a TriviallyCopyable object
	 *
	 * @tparam T Automatically inferred type of object
	 * @param obj Any TriviallyCopyable object
	 */
	template<typename T>
	static ZT_ALWAYS_INLINE void memoryZero(T &obj)
	{
		TriviallyCopyable *const tmp = &obj;
		memset(tmp,0,sizeof(T));
	}

	/**
	 * Copy any memory over a TriviallyCopyable object
	 *
	 * @tparam T Automatically inferred type of destination
	 * @param dest Any TriviallyCopyable object
	 * @param src Source memory of same size or less than sizeof(dest)
	 */
	template<typename T>
	static ZT_ALWAYS_INLINE void memoryCopyUnsafe(T *dest,const void *src)
	{
		TriviallyCopyable *const tmp = dest;
		memcpy(tmp,src,sizeof(T));
	}

	/**
	 * Copy any memory over a TriviallyCopyable object
	 *
	 * @tparam T Automatically inferred type of destination
	 * @param dest Any TriviallyCopyable object
	 * @param src Source memory of same size or less than sizeof(dest)
	 */
	template<typename T>
	static ZT_ALWAYS_INLINE void memoryCopyUnsafe(T &dest,const void *src)
	{
		TriviallyCopyable *const tmp = &dest;
		memcpy(tmp,src,sizeof(T));
	}

	/**
	 * Copy a TriviallyCopyable object
	 *
	 * @tparam T Automatically inferred type of destination
	 * @param dest Destination TriviallyCopyable object
	 * @param src Source TriviallyCopyable object
	 */
	template<typename T>
	static ZT_ALWAYS_INLINE void memoryCopy(T *dest,const T *src)
	{
		TriviallyCopyable *const tmp = dest;
		memcpy(tmp,src,sizeof(T));
	}

	/**
	 * Copy a TriviallyCopyable object
	 *
	 * @tparam T Automatically inferred type of destination
	 * @param dest Destination TriviallyCopyable object
	 * @param src Source TriviallyCopyable object
	 */
	template<typename T>
	static ZT_ALWAYS_INLINE void memoryCopy(T *dest,const T &src)
	{
		TriviallyCopyable *const tmp = dest;
		memcpy(tmp,&src,sizeof(T));
	}

	/**
	 * Copy a TriviallyCopyable object
	 *
	 * @tparam T Automatically inferred type of destination
	 * @param dest Destination TriviallyCopyable object
	 * @param src Source TriviallyCopyable object
	 */
	template<typename T>
	static ZT_ALWAYS_INLINE void memoryCopy(T &dest,const T *src)
	{
		TriviallyCopyable *const tmp = &dest;
		memcpy(tmp,src,sizeof(T));
	}

	/**
	 * Copy a TriviallyCopyable object
	 *
	 * @tparam T Automatically inferred type of destination
	 * @param dest Destination TriviallyCopyable object
	 * @param src Source TriviallyCopyable object
	 */
	template<typename T>
	static ZT_ALWAYS_INLINE void memoryCopy(T &dest,const T &src)
	{
		TriviallyCopyable *const tmp = &dest;
		memcpy(tmp,&src,sizeof(T));
	}
};

} // namespace ZeroTier

#endif
