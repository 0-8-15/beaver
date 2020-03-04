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

#ifndef ZT_REVOCATION_HPP
#define ZT_REVOCATION_HPP

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>

#include "Constants.hpp"
#include "Credential.hpp"
#include "Address.hpp"
#include "C25519.hpp"
#include "Utils.hpp"
#include "Identity.hpp"

/**
 * Flag: fast propagation via rumor mill algorithm
 */
#define ZT_REVOCATION_FLAG_FAST_PROPAGATE 0x1ULL

#define ZT_REVOCATION_MARSHAL_SIZE_MAX (4 + 4 + 8 + 4 + 4 + 8 + 8 + 5 + 5 + 1 + 1 + 2 + ZT_SIGNATURE_BUFFER_SIZE + 2)

namespace ZeroTier {

class RuntimeEnvironment;

/**
 * Revocation certificate to instantaneously revoke a COM, capability, or tag
 */
class Revocation : public Credential
{
	friend class Credential;

public:
	static constexpr ZT_CredentialType credentialType() noexcept { return ZT_CREDENTIAL_TYPE_REVOCATION; }

	ZT_INLINE Revocation() noexcept { memoryZero(this); }

	/**
	 * @param i ID (arbitrary for revocations, currently random)
	 * @param nwid Network ID
	 * @param cid Credential ID being revoked (0 for all or for COMs, which lack IDs)
	 * @param thr Revocation time threshold before which credentials will be revoked
	 * @param fl Flags
	 * @param tgt Target node whose credential(s) are being revoked
	 * @param ct Credential type being revoked
	 */
	ZT_INLINE Revocation(const uint32_t i,const uint64_t nwid,const uint32_t cid,const uint64_t thr,const uint64_t fl,const Address &tgt,const ZT_CredentialType ct) noexcept :
		_id(i),
		_credentialId(cid),
		_networkId(nwid),
		_threshold(thr),
		_flags(fl),
		_target(tgt),
		_signedBy(),
		_type(ct),
		_signatureLength(0)
	{
	}

	ZT_INLINE uint32_t id() const noexcept { return _id; }
	ZT_INLINE uint32_t credentialId() const noexcept { return _credentialId; }
	ZT_INLINE uint64_t networkId() const noexcept { return _networkId; }
	ZT_INLINE int64_t threshold() const noexcept { return _threshold; }
	ZT_INLINE const Address &target() const noexcept { return _target; }
	ZT_INLINE const Address &signer() const noexcept { return _signedBy; }
	ZT_INLINE ZT_CredentialType typeBeingRevoked() const noexcept { return _type; }
	ZT_INLINE const uint8_t *signature() const noexcept { return _signature; }
	ZT_INLINE unsigned int signatureLength() const noexcept { return _signatureLength; }
	ZT_INLINE bool fastPropagate() const noexcept { return ((_flags & ZT_REVOCATION_FLAG_FAST_PROPAGATE) != 0); }

	/**
	 * @param signer Signing identity, must have private key
	 * @return True if signature was successful
	 */
	bool sign(const Identity &signer) noexcept;

	/**
	 * Verify this revocation's signature
	 *
	 * @param RR Runtime environment to provide for peer lookup, etc.
	 * @param tPtr Thread pointer to be handed through to any callbacks called as a result of this call
	 */
	ZT_INLINE Credential::VerifyResult verify(const RuntimeEnvironment *RR,void *tPtr) const noexcept { return _verify(RR,tPtr,*this); }

	static constexpr int marshalSizeMax() noexcept { return ZT_REVOCATION_MARSHAL_SIZE_MAX; }
	int marshal(uint8_t data[ZT_REVOCATION_MARSHAL_SIZE_MAX],bool forSign = false) const noexcept;
	int unmarshal(const uint8_t *restrict data,int len) noexcept;

private:
	uint32_t _id;
	uint32_t _credentialId;
	uint64_t _networkId;
	int64_t _threshold;
	uint64_t _flags;
	Address _target;
	Address _signedBy;
	ZT_CredentialType _type;
	unsigned int _signatureLength;
	uint8_t _signature[ZT_SIGNATURE_BUFFER_SIZE];
};

} // namespace ZeroTier

#endif
