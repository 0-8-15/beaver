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

#ifndef ZT_TOPOLOGY_HPP
#define ZT_TOPOLOGY_HPP

#include <stdio.h>
#include <string.h>

#include <vector>
#include <stdexcept>
#include <algorithm>
#include <utility>

#include "Constants.hpp"
#include "../include/ZeroTierOne.h"

#include "Address.hpp"
#include "Identity.hpp"
#include "Peer.hpp"
#include "Path.hpp"
#include "Mutex.hpp"
#include "InetAddress.hpp"
#include "Hashtable.hpp"
#include "Root.hpp"
#include "SharedPtr.hpp"

namespace ZeroTier {

class RuntimeEnvironment;

/**
 * Database of network topology
 */
class Topology
{
public:
	inline Topology(const RuntimeEnvironment *renv,const Identity &myId) :
		RR(renv),
		_myIdentity(myId),
		_numConfiguredPhysicalPaths(0) {}
	inline ~Topology() {}

	/**
	 * Add a peer to database
	 *
	 * This will not replace existing peers. In that case the existing peer
	 * record is returned.
	 *
	 * @param tPtr Thread pointer to be handed through to any callbacks called as a result of this call
	 * @param peer Peer to add
	 * @return New or existing peer (should replace 'peer')
	 */
	inline SharedPtr<Peer> add(const SharedPtr<Peer> &peer)
	{
		SharedPtr<Peer> np;
		{
			Mutex::Lock _l(_peers_m);
			SharedPtr<Peer> &hp = _peers[peer->address()];
			if (!hp)
				hp = peer;
			np = hp;
		}
		return np;
	}

	/**
	 * Get a peer from its address
	 *
	 * @param tPtr Thread pointer to be handed through to any callbacks called as a result of this call
	 * @param zta ZeroTier address of peer
	 * @return Peer or NULL if not found
	 */
	inline SharedPtr<Peer> get(const Address &zta)
	{
		if (zta == _myIdentity.address())
			return SharedPtr<Peer>();

		Mutex::Lock l1(_peers_m);
		const SharedPtr<Peer> *const ap = _peers.get(zta);
		if (ap)
			return *ap;

		Mutex::Lock l2(_roots_m);
		for(std::vector<Root>::const_iterator r(_roots.begin());r!=_roots.end();++r) {
			if (r->address() == zta) {
				try {
					SharedPtr<Peer> rp(new Peer(RR,_myIdentity,r->id()));
					_peers[zta] = rp;
					return rp;
				} catch ( ... ) {}
			}
		}

		return SharedPtr<Peer>();
	}

	/**
	 * @param tPtr Thread pointer to be handed through to any callbacks called as a result of this call
	 * @param zta ZeroTier address of peer
	 * @return Identity or NULL identity if not found
	 */
	inline Identity getIdentity(void *tPtr,const Address &zta)
	{
		if (zta == _myIdentity.address()) {
			return _myIdentity;
		} else {
			Mutex::Lock _l(_peers_m);
			const SharedPtr<Peer> *const ap = _peers.get(zta);
			if (ap)
				return (*ap)->identity();
		}
		return Identity();
	}

	/**
	 * Get a Path object for a given local and remote physical address, creating if needed
	 *
	 * @param l Local socket
	 * @param r Remote address
	 * @return Pointer to canonicalized Path object
	 */
	inline SharedPtr<Path> getPath(const int64_t l,const InetAddress &r)
	{
		Mutex::Lock _l(_paths_m);
		SharedPtr<Path> &p = _paths[Path::HashKey(l,r)];
		if (!p)
			p.set(new Path(l,r));
		return p;
	}

	/**
	 * @param id Identity to check
	 * @return True if this identity corresponds to a root
	 */
	inline bool isRoot(const Identity &id) const
	{
		Mutex::Lock l(_roots_m);
		for(std::vector<Root>::const_iterator r(_roots.begin());r!=_roots.end();++r) {
			if (r->is(id))
				return true;
		}
		return false;
	}

	/**
	 * Do periodic tasks such as database cleanup
	 */
	inline void doPeriodicTasks(int64_t now)
	{
		{
			Mutex::Lock _l1(_peers_m);
			Hashtable< Address,SharedPtr<Peer> >::Iterator i(_peers);
			Address *a = (Address *)0;
			SharedPtr<Peer> *p = (SharedPtr<Peer> *)0;
			while (i.next(a,p)) {
				if (!(*p)->alive(now)) {
					_peers.erase(*a);
				}
			}
		}
		{
			Mutex::Lock _l(_paths_m);
			Hashtable< Path::HashKey,SharedPtr<Path> >::Iterator i(_paths);
			Path::HashKey *k = (Path::HashKey *)0;
			SharedPtr<Path> *p = (SharedPtr<Path> *)0;
			while (i.next(k,p)) {
				if (p->references() <= 1)
					_paths.erase(*k);
			}
		}
	}

	/**
	 * @param now Current time
	 * @return Number of peers with active direct paths
	 */
	inline unsigned long countActive(int64_t now) const
	{
		unsigned long cnt = 0;
		Mutex::Lock _l(_peers_m);
		Hashtable< Address,SharedPtr<Peer> >::Iterator i(const_cast<Topology *>(this)->_peers);
		Address *a = (Address *)0;
		SharedPtr<Peer> *p = (SharedPtr<Peer> *)0;
		while (i.next(a,p)) {
			const SharedPtr<Path> pp((*p)->getAppropriatePath(now,false));
			if (pp)
				++cnt;
		}
		return cnt;
	}

	/**
	 * Apply a function or function object to all peers
	 *
	 * This locks the peer map during execution, so calls to get() etc. during
	 * eachPeer() will deadlock.
	 *
	 * @param f Function to apply
	 * @tparam F Function or function object type
	 */
	template<typename F>
	inline void eachPeer(F f)
	{
		Mutex::Lock l(_peers_m);
		Hashtable< Address,SharedPtr<Peer> >::Iterator i(_peers);
		Address *a = (Address *)0;
		SharedPtr<Peer> *p = (SharedPtr<Peer> *)0;
		while (i.next(a,p)) {
			f(*((const SharedPtr<Peer> *)p));
		}
	}

	/**
	 * Apply a function or function object to all roots
	 *
	 * This locks the root list during execution but other operations
	 * are fine.
	 *
	 * @param f Function to apply
	 * @tparam F function or function object type
	 */
	template<typename F>
	inline void eachRoot(F f)
	{
		Mutex::Lock l(_roots_m);
		SharedPtr<Peer> rp;
		for(std::vector<Root>::const_iterator i(_roots.begin());i!=_roots.end();++i) {
			{
				Mutex::Lock l2(_peers_m);
				const SharedPtr<Peer> *const ap = _peers.get(i->address());
				if (ap) {
					rp = *ap;
				} else {
					rp.set(new Peer(RR,_myIdentity,i->id()));
					_peers.set(rp->address(),rp);
				}
			}
			f(*i,rp);
		}
	}

	/**
	 * Get the best root, rescanning and re-ranking roots periodically
	 *
	 * @param now Current time
	 * @return Best/fastest currently connected root or NULL if none
	 */
	inline SharedPtr<Peer> root(const int64_t now)
	{
		Mutex::Lock l(_bestRoot_m);
		if ((!_bestRoot)||((now - _lastRankedBestRoot) >= ZT_FIND_BEST_ROOT_PERIOD)) {
			_bestRoot.zero();
			Mutex::Lock l2(_roots_m);
			SharedPtr<Peer> rp;
			long bestQuality = 2147483647;
			for(std::vector<Root>::const_iterator i(_roots.begin());i!=_roots.end();++i) {
				{
					Mutex::Lock l2(_peers_m);
					const SharedPtr<Peer> *const ap = _peers.get(i->address());
					if (ap) {
						rp = *ap;
					} else {
						rp.set(new Peer(RR,_myIdentity,i->id()));
						_peers.set(rp->address(),rp);
					}
				}
				SharedPtr<Path> path(rp->getAppropriatePath(now,false));
				if (path) {
					const long pq = path->quality(now);
					if (pq < bestQuality) {
						bestQuality = pq;
						_bestRoot = rp;
					}
				}
			}
		}
		return _bestRoot;
	}

	/**
	 * Get the best relay to a given address, which may or may not be a root
	 *
	 * @param now Current time
	 * @param toAddr Destination address
	 * @return Best current relay or NULL if none
	 */
	inline SharedPtr<Peer> findRelayTo(const int64_t now,const Address &toAddr)
	{
		// TODO: in the future this will check 'mesh-like' relays and if enabled consult LF for other roots (for if this is a root)
		return root(now);
	}

	/**
	 * @param allPeers vector to fill with all current peers
	 */
	inline void getAllPeers(std::vector< SharedPtr<Peer> > &allPeers) const
	{
		Mutex::Lock l(_peers_m);
		allPeers.clear();
		allPeers.reserve(_peers.size());
		Hashtable< Address,SharedPtr<Peer> >::Iterator i(*(const_cast<Hashtable< Address,SharedPtr<Peer> > *>(&_peers)));
		Address *a = (Address *)0;
		SharedPtr<Peer> *p = (SharedPtr<Peer> *)0;
		while (i.next(a,p)) {
			allPeers.push_back(*p);
		}
	}

	/**
	 * Get info about a path
	 *
	 * The supplied result variables are not modified if no special config info is found.
	 *
	 * @param physicalAddress Physical endpoint address
	 * @param mtu Variable set to MTU
	 * @param trustedPathId Variable set to trusted path ID
	 */
	inline void getOutboundPathInfo(const InetAddress &physicalAddress,unsigned int &mtu,uint64_t &trustedPathId)
	{
		for(unsigned int i=0,j=_numConfiguredPhysicalPaths;i<j;++i) {
			if (_physicalPathConfig[i].first.containsAddress(physicalAddress)) {
				trustedPathId = _physicalPathConfig[i].second.trustedPathId;
				mtu = _physicalPathConfig[i].second.mtu;
				return;
			}
		}
	}

	/**
	 * Get the payload MTU for an outbound physical path (returns default if not configured)
	 *
	 * @param physicalAddress Physical endpoint address
	 * @return MTU
	 */
	inline unsigned int getOutboundPathMtu(const InetAddress &physicalAddress)
	{
		for(unsigned int i=0,j=_numConfiguredPhysicalPaths;i<j;++i) {
			if (_physicalPathConfig[i].first.containsAddress(physicalAddress))
				return _physicalPathConfig[i].second.mtu;
		}
		return ZT_DEFAULT_PHYSMTU;
	}

	/**
	 * Get the outbound trusted path ID for a physical address, or 0 if none
	 *
	 * @param physicalAddress Physical address to which we are sending the packet
	 * @return Trusted path ID or 0 if none (0 is not a valid trusted path ID)
	 */
	inline uint64_t getOutboundPathTrust(const InetAddress &physicalAddress)
	{
		for(unsigned int i=0,j=_numConfiguredPhysicalPaths;i<j;++i) {
			if (_physicalPathConfig[i].first.containsAddress(physicalAddress))
				return _physicalPathConfig[i].second.trustedPathId;
		}
		return 0;
	}

	/**
	 * Check whether in incoming trusted path marked packet is valid
	 *
	 * @param physicalAddress Originating physical address
	 * @param trustedPathId Trusted path ID from packet (from MAC field)
	 */
	inline bool shouldInboundPathBeTrusted(const InetAddress &physicalAddress,const uint64_t trustedPathId)
	{
		for(unsigned int i=0,j=_numConfiguredPhysicalPaths;i<j;++i) {
			if ((_physicalPathConfig[i].second.trustedPathId == trustedPathId)&&(_physicalPathConfig[i].first.containsAddress(physicalAddress)))
				return true;
		}
		return false;
	}

	/**
	 * Set or clear physical path configuration (called via Node::setPhysicalPathConfiguration)
	 */
	inline void setPhysicalPathConfiguration(const struct sockaddr_storage *pathNetwork,const ZT_PhysicalPathConfiguration *pathConfig)
	{
		if (!pathNetwork) {
			_numConfiguredPhysicalPaths = 0;
		} else {
			std::map<InetAddress,ZT_PhysicalPathConfiguration> cpaths;
			for(unsigned int i=0,j=_numConfiguredPhysicalPaths;i<j;++i)
				cpaths[_physicalPathConfig[i].first] = _physicalPathConfig[i].second;

			if (pathConfig) {
				ZT_PhysicalPathConfiguration pc(*pathConfig);

				if (pc.mtu <= 0)
					pc.mtu = ZT_DEFAULT_PHYSMTU;
				else if (pc.mtu < ZT_MIN_PHYSMTU)
					pc.mtu = ZT_MIN_PHYSMTU;
				else if (pc.mtu > ZT_MAX_PHYSMTU)
					pc.mtu = ZT_MAX_PHYSMTU;

				cpaths[*(reinterpret_cast<const InetAddress *>(pathNetwork))] = pc;
			} else {
				cpaths.erase(*(reinterpret_cast<const InetAddress *>(pathNetwork)));
			}

			unsigned int cnt = 0;
			for(std::map<InetAddress,ZT_PhysicalPathConfiguration>::const_iterator i(cpaths.begin());((i!=cpaths.end())&&(cnt<ZT_MAX_CONFIGURABLE_PATHS));++i) {
				_physicalPathConfig[cnt].first = i->first;
				_physicalPathConfig[cnt].second = i->second;
				++cnt;
			}
			_numConfiguredPhysicalPaths = cnt;
		}
	}

private:
	const RuntimeEnvironment *const RR;
	const Identity _myIdentity;
	std::pair<InetAddress,ZT_PhysicalPathConfiguration> _physicalPathConfig[ZT_MAX_CONFIGURABLE_PATHS];
	unsigned int _numConfiguredPhysicalPaths;
	std::vector<Root> _roots;
	SharedPtr<Peer> _bestRoot;
	int64_t _lastRankedBestRoot;
	Hashtable< Address,SharedPtr<Peer> > _peers;
	Hashtable< Path::HashKey,SharedPtr<Path> > _paths;
	Mutex _roots_m;
	Mutex _bestRoot_m;
	Mutex _peers_m;
	Mutex _paths_m;
};

} // namespace ZeroTier

#endif
