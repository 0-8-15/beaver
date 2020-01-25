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

#ifndef ZT_MAC_HPP
#define ZT_MAC_HPP

#include <cstdio>
#include <cstdlib>
#include <cstdint>

#include "Constants.hpp"
#include "Utils.hpp"
#include "Address.hpp"

namespace ZeroTier {

/**
 * 48-byte Ethernet MAC address
 */
class MAC
{
public:
	ZT_ALWAYS_INLINE MAC() : _m(0ULL) {}
	ZT_ALWAYS_INLINE MAC(const unsigned char a,const unsigned char b,const unsigned char c,const unsigned char d,const unsigned char e,const unsigned char f) :
		_m( ((((uint64_t)a) & 0xffULL) << 40U) |
		    ((((uint64_t)b) & 0xffULL) << 32U) |
		    ((((uint64_t)c) & 0xffULL) << 24U) |
		    ((((uint64_t)d) & 0xffULL) << 16U) |
		    ((((uint64_t)e) & 0xffULL) << 8U) |
		    (((uint64_t)f) & 0xffULL) ) {}
	explicit ZT_ALWAYS_INLINE MAC(const uint8_t b[6]) { setTo(b); }
	ZT_ALWAYS_INLINE MAC(const Address &ztaddr,uint64_t nwid) { fromAddress(ztaddr,nwid); }
	explicit ZT_ALWAYS_INLINE MAC(const uint64_t m) : _m(m & 0xffffffffffffULL) {}

	/**
	 * @return MAC in 64-bit integer
	 */
	ZT_ALWAYS_INLINE uint64_t toInt() const { return _m; }

	/**
	 * Set MAC to zero
	 */
	ZT_ALWAYS_INLINE void zero() { _m = 0ULL; }

	/**
	 * @return True if MAC is non-zero
	 */
	ZT_ALWAYS_INLINE operator bool() const { return (_m != 0ULL); }

	/**
	 * @param bits Raw MAC in big-endian byte order
	 * @param len Length, must be >= 6 or result is zero
	 */
	ZT_ALWAYS_INLINE void setTo(const uint8_t b[6])
	{
		_m = ((uint64_t)b[0] << 40U) | ((uint64_t)b[1] << 32U) | ((uint64_t)b[2] << 24U) | ((uint64_t)b[3] << 16U) | ((uint64_t)b[4] << 8U) | (uint64_t)b[5];
	}

	/**
	 * @param buf Destination buffer for MAC in big-endian byte order
	 * @param len Length of buffer, must be >= 6 or nothing is copied
	 */
	ZT_ALWAYS_INLINE void copyTo(uint8_t b[6]) const
	{
		b[0] = (uint8_t)(_m >> 40U);
		b[1] = (uint8_t)(_m >> 32U);
		b[2] = (uint8_t)(_m >> 24U);
		b[3] = (uint8_t)(_m >> 16U);
		b[4] = (uint8_t)(_m >> 8U);
		b[5] = (uint8_t)_m;
	}

	/**
	 * @return True if this is broadcast (all 0xff)
	 */
	ZT_ALWAYS_INLINE bool isBroadcast() const { return (_m == 0xffffffffffffULL); }

	/**
	 * @return True if this is a multicast MAC
	 */
	ZT_ALWAYS_INLINE bool isMulticast() const { return ((_m & 0x010000000000ULL) != 0ULL); }

	/**
	 * Set this MAC to a MAC derived from an address and a network ID
	 *
	 * @param ztaddr ZeroTier address
	 * @param nwid 64-bit network ID
	 */
	ZT_ALWAYS_INLINE void fromAddress(const Address &ztaddr,uint64_t nwid)
	{
		uint64_t m = ((uint64_t)firstOctetForNetwork(nwid)) << 40U;
		m |= ztaddr.toInt(); // a is 40 bits
		m ^= ((nwid >> 8U) & 0xffU) << 32U;
		m ^= ((nwid >> 16U) & 0xffU) << 24U;
		m ^= ((nwid >> 24U) & 0xffU) << 16U;
		m ^= ((nwid >> 32U) & 0xffU) << 8U;
		m ^= (nwid >> 40U) & 0xffU;
		_m = m;
	}

	/**
	 * Get the ZeroTier address for this MAC on this network (assuming no bridging of course, basic unicast)
	 *
	 * This just XORs the next-lest-significant 5 bytes of the network ID again to unmask.
	 *
	 * @param nwid Network ID
	 */
	ZT_ALWAYS_INLINE Address toAddress(uint64_t nwid) const
	{
		uint64_t a = _m & 0xffffffffffULL; // least significant 40 bits of MAC are formed from address
		a ^= ((nwid >> 8U) & 0xffU) << 32U; // ... XORed with bits 8-48 of the nwid in little-endian byte order, so unmask it
		a ^= ((nwid >> 16U) & 0xffU) << 24U;
		a ^= ((nwid >> 24U) & 0xffU) << 16U;
		a ^= ((nwid >> 32U) & 0xffU) << 8U;
		a ^= (nwid >> 40U) & 0xffU;
		return Address(a);
	}

	/**
	 * @param nwid Network ID
	 * @return First octet of MAC for this network
	 */
	static ZT_ALWAYS_INLINE unsigned char firstOctetForNetwork(uint64_t nwid)
	{
		const uint8_t a = ((uint8_t)(nwid & 0xfeU) | 0x02U); // locally administered, not multicast, from LSB of network ID
		return ((a == 0x52) ? 0x32 : a); // blacklist 0x52 since it's used by KVM, libvirt, and other popular virtualization engines... seems de-facto standard on Linux
	}

	/**
	 * @param i Value from 0 to 5 (inclusive)
	 * @return Byte at said position (address interpreted in big-endian order)
	 */
	ZT_ALWAYS_INLINE uint8_t operator[](unsigned int i) const { return (uint8_t)(_m >> (40 - (i * 8))); }

	/**
	 * @return 6, which is the number of bytes in a MAC, for container compliance
	 */
	ZT_ALWAYS_INLINE unsigned int size() const { return 6; }

	ZT_ALWAYS_INLINE unsigned long hashCode() const { return (unsigned long)_m; }

	ZT_ALWAYS_INLINE char *toString(char buf[18]) const
	{
		buf[0] = Utils::HEXCHARS[(_m >> 44U) & 0xfU];
		buf[1] = Utils::HEXCHARS[(_m >> 40U) & 0xfU];
		buf[2] = ':';
		buf[3] = Utils::HEXCHARS[(_m >> 36U) & 0xfU];
		buf[4] = Utils::HEXCHARS[(_m >> 32U) & 0xfU];
		buf[5] = ':';
		buf[6] = Utils::HEXCHARS[(_m >> 28U) & 0xfU];
		buf[7] = Utils::HEXCHARS[(_m >> 24U) & 0xfU];
		buf[8] = ':';
		buf[9] = Utils::HEXCHARS[(_m >> 20U) & 0xfU];
		buf[10] = Utils::HEXCHARS[(_m >> 16U) & 0xfU];
		buf[11] = ':';
		buf[12] = Utils::HEXCHARS[(_m >> 12U) & 0xfU];
		buf[13] = Utils::HEXCHARS[(_m >> 8U) & 0xfU];
		buf[14] = ':';
		buf[15] = Utils::HEXCHARS[(_m >> 4U) & 0xfU];
		buf[16] = Utils::HEXCHARS[_m & 0xfU];
		buf[17] = (char)0;
		return buf;
	}

	ZT_ALWAYS_INLINE MAC &operator=(const uint64_t m)
	{
		_m = m & 0xffffffffffffULL;
		return *this;
	}

	ZT_ALWAYS_INLINE bool operator==(const MAC &m) const { return (_m == m._m); }
	ZT_ALWAYS_INLINE bool operator!=(const MAC &m) const { return (_m != m._m); }
	ZT_ALWAYS_INLINE bool operator<(const MAC &m) const { return (_m < m._m); }
	ZT_ALWAYS_INLINE bool operator<=(const MAC &m) const { return (_m <= m._m); }
	ZT_ALWAYS_INLINE bool operator>(const MAC &m) const { return (_m > m._m); }
	ZT_ALWAYS_INLINE bool operator>=(const MAC &m) const { return (_m >= m._m); }

private:
	uint64_t _m;
};

} // namespace ZeroTier

#endif
