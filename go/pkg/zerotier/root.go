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

// Root describes a root server used to find and establish communication with other nodes.
type Root struct {
	DNSName   string
	Identity  *Identity
	Addresses []InetAddress
	Locator   Locator
	Preferred bool
	Online    bool
}

// Static returns true if this is a static root
func (r *Root) Static() bool { return len(r.DNSName) == 0 }

// Dynamic returns true if this is a dynamic root
func (r *Root) Dynamic() bool { return len(r.DNSName) > 0 }
