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

#ifndef ZT_TRACE_HPP
#define ZT_TRACE_HPP

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>

#include "Constants.hpp"
#include "SharedPtr.hpp"
#include "Mutex.hpp"
#include "InetAddress.hpp"
#include "Address.hpp"
#include "MAC.hpp"

namespace ZeroTier {

class RuntimeEnvironment;
class Identity;
class Peer;
class Path;
class Network;
class CertificateOfMembership;
class CertificateOfOwnership;
class Revocation;
class Tag;
class Capability;
struct NetworkConfig;

/**
 * Remote tracing and trace logging handler
 */
class Trace
{
public:
	struct RuleResultLog
	{
		uint8_t l[ZT_MAX_NETWORK_RULES / 2]; // ZT_MAX_NETWORK_RULES 4-bit fields

		ZT_ALWAYS_INLINE void log(const unsigned int rn,const uint8_t thisRuleMatches,const uint8_t thisSetMatches)
		{
			l[rn >> 1U] |= ( ((thisRuleMatches + 1U) << 2U) | (thisSetMatches + 1U) ) << ((rn & 1U) << 2U);
		}
		ZT_ALWAYS_INLINE void logSkipped(const unsigned int rn,const uint8_t thisSetMatches)
		{
			l[rn >> 1U] |= (thisSetMatches + 1U) << ((rn & 1U) << 2U);
		}
		ZT_ALWAYS_INLINE void clear()
		{
			memset(l,0,sizeof(l));
		}
	};

	explicit Trace(const RuntimeEnvironment *renv);

	ZT_ALWAYS_INLINE void resettingPathsInScope(
		void *const tPtr,
		const Identity &reporter,
		const InetAddress &from,
		const InetAddress &oldExternal,
		const InetAddress &newExternal,
		const InetAddress::IpScope scope)
	{
		if (_vl1) _resettingPathsInScope(tPtr,reporter,from,oldExternal,newExternal,scope);
	}

	ZT_ALWAYS_INLINE void tryingNewPath(
		void *const tPtr,
		const Identity &trying,
		const InetAddress &physicalAddress,
		const InetAddress &triggerAddress,
		uint64_t triggeringPacketId,
		uint8_t triggeringPacketVerb,
		uint64_t triggeredByAddress,
		const uint8_t *triggeredByIdentityHash,
		ZT_TraceTryingNewPathReason reason)
	{
		if (_vl1) _tryingNewPath(tPtr,trying,physicalAddress,triggerAddress,triggeringPacketId,triggeringPacketVerb,triggeredByAddress,triggeredByIdentityHash,reason);
	}

	ZT_ALWAYS_INLINE void learnedNewPath(
		void *const tPtr,
		uint64_t packetId,
		const Identity &peerIdentity,
		const InetAddress &physicalAddress,
		const InetAddress &replaced)
	{
		if (_vl1) _learnedNewPath(tPtr,packetId,peerIdentity,physicalAddress,replaced);
	}

	ZT_ALWAYS_INLINE void incomingPacketDropped(
		void *const tPtr,
		uint64_t packetId,
		uint64_t networkId,
		const Identity &peerIdentity,
		const InetAddress &physicalAddress,
		uint8_t hops,
		uint8_t verb,
		const ZT_TracePacketDropReason reason)
	{
		if (_vl1) _incomingPacketDropped(tPtr,packetId,networkId,peerIdentity,physicalAddress,hops,verb,reason);
	}

	ZT_ALWAYS_INLINE void outgoingNetworkFrameDropped(
		void *const tPtr,
		uint64_t networkId,
		const MAC &sourceMac,
		const MAC &destMac,
		uint16_t etherType,
		uint16_t frameLength,
		const uint8_t *frameData,
		ZT_TraceFrameDropReason reason)
	{
		if (_vl2) _outgoingNetworkFrameDropped(tPtr,networkId,sourceMac,destMac,etherType,frameLength,frameData,reason);
	}

	ZT_ALWAYS_INLINE void incomingNetworkFrameDropped(
		void *const tPtr,
		uint64_t networkId,
		const MAC &sourceMac,
		const MAC &destMac,
		const Identity &peerIdentity,
		const InetAddress &physicalAddress,
		uint8_t hops,
		uint16_t frameLength,
		const uint8_t *frameData,
		uint8_t verb,
		bool credentialRequestSent,
		ZT_TraceFrameDropReason reason)
	{
		if (_vl2) _incomingNetworkFrameDropped(tPtr,networkId,sourceMac,destMac,peerIdentity,physicalAddress,hops,frameLength,frameData,verb,credentialRequestSent,reason);
	}

	ZT_ALWAYS_INLINE void networkConfigRequestSent(
		void *const tPtr,
		uint64_t networkId)
	{
		if (_vl2) _networkConfigRequestSent(tPtr,networkId);
	}

	ZT_ALWAYS_INLINE void networkFilter(
		void *const tPtr,
		uint64_t networkId,
		const uint8_t primaryRuleSetLog[512],
		const uint8_t matchingCapabilityRuleSetLog[512],
		uint32_t matchingCapabilityId,
		int64_t matchingCapabilityTimestamp,
		const Address &source,
		const Address &dest,
		const MAC &sourceMac,
		const MAC &destMac,
		uint16_t frameLength,
		const uint8_t *frameData,
		uint16_t etherType,
		uint16_t vlanId,
		bool noTee,
		bool inbound,
		int accept)
	{
		if (_vl2Filter) {
			_networkFilter(
				tPtr,
				networkId,
				primaryRuleSetLog,
				matchingCapabilityRuleSetLog,
				matchingCapabilityId,
				matchingCapabilityTimestamp,
				source,
				dest,
				sourceMac,
				destMac,
				frameLength,
				frameData,
				etherType,
				vlanId,
				noTee,
				inbound,
				accept);
		}
	}

	ZT_ALWAYS_INLINE void credentialRejected(
		void *const tPtr,
		uint64_t networkId,
		const Address &address,
		uint32_t credentialId,
		int64_t credentialTimestamp,
		uint8_t credentialType,
		ZT_TraceCredentialRejectionReason reason)
	{
		if (_vl2) _credentialRejected(tPtr,networkId,address,credentialId,credentialTimestamp,credentialType,reason);
	}

private:
	void _resettingPathsInScope(
		void *tPtr,
		const Identity &reporter,
		const InetAddress &from,
		const InetAddress &oldExternal,
		const InetAddress &newExternal,
		InetAddress::IpScope scope);
	void _tryingNewPath(
		void *tPtr,
		const Identity &trying,
		const InetAddress &physicalAddress,
		const InetAddress &triggerAddress,
		uint64_t triggeringPacketId,
		uint8_t triggeringPacketVerb,
		uint64_t triggeredByAddress,
		const uint8_t *triggeredByIdentityHash,
		ZT_TraceTryingNewPathReason reason);
	void _learnedNewPath(
		void *tPtr,
		uint64_t packetId,
		const Identity &peerIdentity,
		const InetAddress &physicalAddress,
		const InetAddress &replaced);
	void _incomingPacketDropped(
		void *tPtr,
		uint64_t packetId,
		uint64_t networkId,
		const Identity &peerIdentity,
		const InetAddress &physicalAddress,
		uint8_t hops,
		uint8_t verb,
		ZT_TracePacketDropReason reason);
	void _outgoingNetworkFrameDropped(
		void *tPtr,
		uint64_t networkId,
		const MAC &sourceMac,
		const MAC &destMac,
		uint16_t etherType,
		uint16_t frameLength,
		const uint8_t *frameData,
		ZT_TraceFrameDropReason reason);
	void _incomingNetworkFrameDropped(
		void *const tPtr,
		uint64_t networkId,
		const MAC &sourceMac,
		const MAC &destMac,
		const Identity &peerIdentity,
		const InetAddress &physicalAddress,
		uint8_t hops,
		uint16_t frameLength,
		const uint8_t *frameData,
		uint8_t verb,
		bool credentialRequestSent,
		ZT_TraceFrameDropReason reason);
	void _networkConfigRequestSent(
		void *tPtr,
		uint64_t networkId);
	void _networkFilter(
		void *tPtr,
		uint64_t networkId,
		const uint8_t primaryRuleSetLog[512],
		const uint8_t matchingCapabilityRuleSetLog[512],
		uint32_t matchingCapabilityId,
		int64_t matchingCapabilityTimestamp,
		const Address &source,
		const Address &dest,
		const MAC &sourceMac,
		const MAC &destMac,
		uint16_t frameLength,
		const uint8_t *frameData,
		uint16_t etherType,
		uint16_t vlanId,
		bool noTee,
		bool inbound,
		int accept);
	void _credentialRejected(
		void *tPtr,
		uint64_t networkId,
		const Address &address,
		uint32_t credentialId,
		int64_t credentialTimestamp,
		uint8_t credentialType,
		ZT_TraceCredentialRejectionReason reason);

	const RuntimeEnvironment *const RR;
	volatile bool _vl1,_vl2,_vl2Filter,_vl2Multicast;

	struct _MonitoringPeer
	{
		int64_t _timeSet;
		unsigned int _traceTypes;
		SharedPtr<Peer> peer;
		Mutex lock;
	};

	uint8_t _eventBuf[8192]; // must be less than ZT_PROTO_MAX_PACKET_LENGTH
	unsigned int _eventBufSize;

	std::vector<_MonitoringPeer> _monitoringPeers;
	RWMutex _monitoringPeers_l;
};

} // namespace ZeroTier

#endif
