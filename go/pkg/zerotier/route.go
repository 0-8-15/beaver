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

package zerotier

import (
	"net"
	"unsafe"
)

// Route represents a route in a host's routing table
type Route struct {
	// Target for this route
	Target net.IPNet

	// Via is how to reach this target (null/empty if the target IP range is local to this virtual LAN)
	Via net.IP

	// Route flags (currently unused, always 0)
	Flags uint16

	// Metric is an interface metric that can affect route priority (behavior can be OS-specific)
	Metric uint16
}

// key generates a key suitable for a map[] from this route
func (r *Route) key() (k [6]uint64) {
	copy(((*[16]byte)(unsafe.Pointer(&k[0])))[:], r.Target.IP)
	ones, bits := r.Target.Mask.Size()
	k[2] = (uint64(ones) << 32) | uint64(bits)
	copy(((*[16]byte)(unsafe.Pointer(&k[3])))[:], r.Via)
	k[5] = (uint64(r.Flags) << 32) | uint64(r.Metric)
	return
}
