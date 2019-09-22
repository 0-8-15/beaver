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

// MulticastGroup represents a normal Ethernet multicast or broadcast address plus 32 additional ZeroTier-specific bits
type MulticastGroup struct {
	MAC MAC
	ADI uint32
}

// Less returns true if this MulticastGroup is less than another.
func (mg *MulticastGroup) Less(mg2 *MulticastGroup) bool {
	return (mg.MAC < mg2.MAC || (mg.MAC == mg2.MAC && mg.ADI < mg2.ADI))
}

// key returns an array usable as a key for a map[]
func (mg *MulticastGroup) key() (k [2]uint64) {
	k[0] = uint64(mg.MAC)
	k[1] = uint64(mg.ADI)
	return
}
