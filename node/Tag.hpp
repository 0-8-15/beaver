/*
 * ZeroTier One - Network Virtualization Everywhere
 * Copyright (C) 2011-2019  ZeroTier, Inc.  https://www.zerotier.com/
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
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * --
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial closed-source software that incorporates or links
 * directly against ZeroTier software without disclosing the source code
 * of your own application.
 */

#ifndef ZT_TAG_HPP
#define ZT_TAG_HPP

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Constants.hpp"
#include "Credential.hpp"
#include "C25519.hpp"
#include "Address.hpp"
#include "Identity.hpp"
#include "Buffer.hpp"

namespace ZeroTier {

class RuntimeEnvironment;

/**
 * A tag that can be associated with members and matched in rules
 *
 * Capabilities group rules, while tags group members subject to those
 * rules. Tag values can be matched in rules, and tags relevant to a
 * capability are presented along with it.
 *
 * E.g. a capability might be "can speak Samba/CIFS within your
 * department." This cap might have a rule to allow TCP/137 but
 * only if a given tag ID's value matches between two peers. The
 * capability is what members can do, while the tag is who they are.
 * Different departments might have tags with the same ID but different
 * values.
 *
 * Unlike capabilities tags are signed only by the issuer and are never
 * transferable.
 */
class Tag : public Credential
{
public:
	static inline Credential::Type credentialType() { return Credential::CREDENTIAL_TYPE_TAG; }

	inline Tag() :
		_id(0),
		_value(0),
		_networkId(0),
		_ts(0),
		_signatureLength(0)
	{
	}

	/**
	 * @param nwid Network ID
	 * @param ts Timestamp
	 * @param issuedTo Address to which this tag was issued
	 * @param id Tag ID
	 * @param value Tag value
	 */
	inline Tag(const uint64_t nwid,const int64_t ts,const Address &issuedTo,const uint32_t id,const uint32_t value) :
		_id(id),
		_value(value),
		_networkId(nwid),
		_ts(ts),
		_issuedTo(issuedTo),
		_signedBy(),
		_signatureLength(0)
	{
	}

	inline uint32_t id() const { return _id; }
	inline const uint32_t &value() const { return _value; }
	inline uint64_t networkId() const { return _networkId; }
	inline int64_t timestamp() const { return _ts; }
	inline const Address &issuedTo() const { return _issuedTo; }
	inline const Address &signedBy() const { return _signedBy; }

	/**
	 * Sign this tag
	 *
	 * @param signer Signing identity, must have private key
	 * @return True if signature was successful
	 */
	bool sign(const Identity &signer);

	/**
	 * Check this tag's signature
	 *
	 * @param RR Runtime environment to allow identity lookup for signedBy
	 * @param tPtr Thread pointer to be handed through to any callbacks called as a result of this call
	 * @return 0 == OK, 1 == waiting for WHOIS, -1 == BAD signature or tag
	 */
	int verify(const RuntimeEnvironment *RR,void *tPtr) const;

	template<unsigned int C>
	inline void serialize(Buffer<C> &b,const bool forSign = false) const
	{
		if (forSign) b.append((uint64_t)0x7f7f7f7f7f7f7f7fULL);

		b.append(_networkId);
		b.append(_ts);
		b.append(_id);
		b.append(_value);

		_issuedTo.appendTo(b);
		_signedBy.appendTo(b);
		if (!forSign) {
			b.append((uint8_t)1);
			b.append((uint16_t)_signatureLength);
			b.append(_signature,_signatureLength);
		}

		b.append((uint16_t)0); // length of additional fields, currently 0

		if (forSign) b.append((uint64_t)0x7f7f7f7f7f7f7f7fULL);
	}

	template<unsigned int C>
	inline unsigned int deserialize(const Buffer<C> &b,unsigned int startAt = 0)
	{
		unsigned int p = startAt;

		*this = Tag();

		_networkId = b.template at<uint64_t>(p); p += 8;
		_ts = b.template at<uint64_t>(p); p += 8;
		_id = b.template at<uint32_t>(p); p += 4;

		_value = b.template at<uint32_t>(p); p += 4;

		_issuedTo.setTo(b.field(p,ZT_ADDRESS_LENGTH),ZT_ADDRESS_LENGTH); p += ZT_ADDRESS_LENGTH;
		_signedBy.setTo(b.field(p,ZT_ADDRESS_LENGTH),ZT_ADDRESS_LENGTH); p += ZT_ADDRESS_LENGTH;
		if (b[p++] == 1) {
			_signatureLength = b.template at<uint16_t>(p);
			if (_signatureLength > sizeof(_signature))
				throw ZT_EXCEPTION_INVALID_SERIALIZED_DATA_INVALID_CRYPTOGRAPHIC_TOKEN;
			p += 2;
			memcpy(_signature,b.field(p,_signatureLength),_signatureLength); p += _signatureLength;
		} else {
			p += 2 + b.template at<uint16_t>(p);
		}

		p += 2 + b.template at<uint16_t>(p);
		if (p > b.size())
			throw ZT_EXCEPTION_INVALID_SERIALIZED_DATA_OVERFLOW;

		return (p - startAt);
	}

	// Provides natural sort order by ID
	inline bool operator<(const Tag &t) const { return (_id < t._id); }

	inline bool operator==(const Tag &t) const { return (memcmp(this,&t,sizeof(Tag)) == 0); }
	inline bool operator!=(const Tag &t) const { return (memcmp(this,&t,sizeof(Tag)) != 0); }

	// For searching sorted arrays or lists of Tags by ID
	struct IdComparePredicate
	{
		inline bool operator()(const Tag &a,const Tag &b) const { return (a.id() < b.id()); }
		inline bool operator()(const uint32_t a,const Tag &b) const { return (a < b.id()); }
		inline bool operator()(const Tag &a,const uint32_t b) const { return (a.id() < b); }
		inline bool operator()(const Tag *a,const Tag *b) const { return (a->id() < b->id()); }
		inline bool operator()(const Tag *a,const Tag &b) const { return (a->id() < b.id()); }
		inline bool operator()(const Tag &a,const Tag *b) const { return (a.id() < b->id()); }
		inline bool operator()(const uint32_t a,const Tag *b) const { return (a < b->id()); }
		inline bool operator()(const Tag *a,const uint32_t b) const { return (a->id() < b); }
		inline bool operator()(const uint32_t a,const uint32_t b) const { return (a < b); }
	};

private:
	uint32_t _id;
	uint32_t _value;
	uint64_t _networkId;
	int64_t _ts;
	Address _issuedTo;
	Address _signedBy;
	unsigned int _signatureLength;
	uint8_t _signature[ZT_SIGNATURE_BUFFER_SIZE];
};

} // namespace ZeroTier

#endif
