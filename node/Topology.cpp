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

#include "Topology.hpp"

namespace ZeroTier {

const uint64_t Topology::s_pathHashSalt = Utils::getSecureRandomU64();

// Sorts roots so as to put the lowest latency alive root first.
struct _RootSortComparisonOperator
{
	ZT_INLINE _RootSortComparisonOperator(const int64_t now) : _now(now) {}
	ZT_INLINE bool operator()(const SharedPtr<Peer> &a,const SharedPtr<Peer> &b)
	{
		const int64_t now = _now;
		if (a->active(now)) {
			if (b->active(now))
				return (a->latency() < b->latency());
			return true;
		}
		return a->lastReceive() < b->lastReceive();
	}
	const int64_t _now;
};

Topology::Topology(const RuntimeEnvironment *renv,void *tPtr) :
	RR(renv),
	_numConfiguredPhysicalPaths(0)
{
	uint64_t idtmp[2]; idtmp[0] = 0; idtmp[1] = 0;
	std::vector<uint8_t> data(RR->node->stateObjectGet(tPtr,ZT_STATE_OBJECT_ROOTS,idtmp));
	if (!data.empty()) {
		uint8_t *dptr = data.data();
		int drem = (int)data.size();
		while (drem > 0) {
			Identity id;
			int l = id.unmarshal(dptr,drem);
			if (l > 0) {
				_roots.insert(id);
				dptr += l;
				drem -= l;
			}
		}
	}

	for(std::set<Identity>::const_iterator r(_roots.begin());r!=_roots.end();++r) {
		SharedPtr<Peer> p;
		_loadCached(tPtr,r->address(),p);
		if ((!p)||(p->identity() != *r)) {
			p.set(new Peer(RR));
			p->init(*r);
		}
		_rootPeers.push_back(p);
		_peers[p->address()] = p;
		_peersByIncomingProbe[p->incomingProbe()] = p;
		_peersByIdentityHash[p->identity().fingerprint()] = p;
	}
}

Topology::~Topology()
{
}

SharedPtr<Peer> Topology::add(void *tPtr,const SharedPtr<Peer> &peer)
{
	RWMutex::Lock _l(_peers_l);

	SharedPtr<Peer> &hp = _peers[peer->address()];
	if (hp)
		return hp;

	_loadCached(tPtr,peer->address(),hp);
	if (hp) {
		_peersByIncomingProbe[peer->incomingProbe()] = hp;
		_peersByIdentityHash[peer->identity().fingerprint()] = hp;
		return hp;
	}

	hp = peer;
	_peersByIncomingProbe[peer->incomingProbe()] = peer;
	_peersByIdentityHash[peer->identity().fingerprint()] = peer;

	return peer;
}

void Topology::getAllPeers(std::vector< SharedPtr<Peer> > &allPeers) const
{
	RWMutex::RLock l(_peers_l);
	allPeers.clear();
	allPeers.reserve(_peers.size());
	for(FlatMap< Address,SharedPtr<Peer> >::const_iterator i(_peers.begin());i!=_peers.end();++i)
		allPeers.push_back(i->second);
}

void Topology::setPhysicalPathConfiguration(const struct sockaddr_storage *pathNetwork,const ZT_PhysicalPathConfiguration *pathConfig)
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
				pc.mtu = ZT_DEFAULT_UDP_MTU;
			else if (pc.mtu < ZT_MIN_UDP_MTU)
				pc.mtu = ZT_MIN_UDP_MTU;
			else if (pc.mtu > ZT_MAX_UDP_MTU)
				pc.mtu = ZT_MAX_UDP_MTU;

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

void Topology::addRoot(void *tPtr,const Identity &id,const InetAddress &bootstrap)
{
	if (id == RR->identity) return; // sanity check
	RWMutex::Lock l1(_peers_l);
	std::pair< std::set<Identity>::iterator,bool > ir(_roots.insert(id));
	if (ir.second) {
		SharedPtr<Peer> &p = _peers[id.address()];
		if (!p) {
			p.set(new Peer(RR));
			p->init(id);
			if (bootstrap)
				p->setBootstrap(Endpoint(bootstrap));
			_peersByIncomingProbe[p->incomingProbe()] = p;
			_peersByIdentityHash[p->identity().fingerprint()] = p;
		}
		_rootPeers.push_back(p);

		uint8_t *const roots = (uint8_t *)malloc(ZT_IDENTITY_MARSHAL_SIZE_MAX * _roots.size());
		if (roots) {
			int p = 0;
			for(std::set<Identity>::const_iterator i(_roots.begin());i!=_roots.end();++i) {
				int pp = i->marshal(roots + p,false);
				if (pp > 0)
					p += pp;
			}
			uint64_t id[2];
			id[0] = 0;
			id[1] = 0;
			RR->node->stateObjectPut(tPtr,ZT_STATE_OBJECT_ROOTS,id,roots,(unsigned int)p);
			free(roots);
		}
	}
}

bool Topology::removeRoot(const Identity &id)
{
	RWMutex::Lock l1(_peers_l);
	std::set<Identity>::iterator r(_roots.find(id));
	if (r != _roots.end()) {
		for(std::vector< SharedPtr<Peer> >::iterator p(_rootPeers.begin());p!=_rootPeers.end();++p) {
			if ((*p)->identity() == id) {
				_rootPeers.erase(p);
				break;
			}
		}
		_roots.erase(r);
		return true;
	}
	return false;
}

void Topology::rankRoots(const int64_t now)
{
	RWMutex::Lock l1(_peers_l);
	std::sort(_rootPeers.begin(),_rootPeers.end(),_RootSortComparisonOperator(now));
}

void Topology::doPeriodicTasks(void *tPtr,const int64_t now)
{
	{
		RWMutex::Lock l1(_peers_l);
		for(FlatMap< Address,SharedPtr<Peer> >::iterator i(_peers.begin());i!=_peers.end();) {
			if ( (!i->second->alive(now)) && (_roots.count(i->second->identity()) == 0) ) {
				i->second->save(tPtr);
				_peersByIncomingProbe.erase(i->second->incomingProbe());
				_peersByIdentityHash.erase(i->second->identity().fingerprint());
				_peers.erase(i++);
			} else ++i;
		}
	}
	{
		RWMutex::Lock l1(_paths_l);
		for(FlatMap< uint64_t,SharedPtr<Path> >::iterator i(_paths.begin());i!=_paths.end();) {
			if ((i->second.references() <= 1)&&(!i->second->alive(now)))
				_paths.erase(i++);
			else ++i;
		}
	}
}

void Topology::saveAll(void *tPtr)
{
	RWMutex::RLock l(_peers_l);
	for(FlatMap< Address,SharedPtr<Peer> >::iterator i(_peers.begin());i!=_peers.end();++i)
		i->second->save(tPtr);
}

void Topology::_loadCached(void *tPtr,const Address &zta,SharedPtr<Peer> &peer)
{
	try {
		uint64_t id[2];
		id[0] = zta.toInt();
		id[1] = 0;
		std::vector<uint8_t> data(RR->node->stateObjectGet(tPtr,ZT_STATE_OBJECT_PEER,id));
		if (data.size() > 8) {
			const uint8_t *d = data.data();
			int dl = (int)data.size();

			const int64_t ts = (int64_t)Utils::loadBigEndian<uint64_t>(d);
			Peer *const p = new Peer(RR);
			int n = p->unmarshal(d + 8,dl - 8);
			if (n < 0) {
				delete p;
				return;
			}
			if ((RR->node->now() - ts) < ZT_PEER_GLOBAL_TIMEOUT) {
				// TODO: handle many peers, same address (?)
				peer.set(p);
				return;
			}
		}
	} catch ( ... ) {
		peer.zero();
	}
}

} // namespace ZeroTier
