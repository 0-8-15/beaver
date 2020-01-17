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

package cli

import (
	"fmt"

	"zerotier/pkg/zerotier"
)

var copyrightText = fmt.Sprintf(`ZeroTier Network Virtualization Service Version %d.%d.%d
(c)2019 ZeroTier, Inc.
Licensed under the ZeroTier BSL (see LICENSE.txt)`, zerotier.CoreVersionMajor, zerotier.CoreVersionMinor, zerotier.CoreVersionRevision)

// Help dumps help to stdout
func Help() {
	fmt.Println(copyrightText)
	fmt.Println(`
Usage: zerotier [-options] <command> [command args]

Global Options:
  -j                                   Output raw JSON where applicable
  -p <path>                            Use alternate base path
  -t <path>                            Use secret auth token from this file

Commands:
  help                                 Show this help
  version                              Print version
  selftest                             Run internal tests
  service                              Start as service
  status                               Show ZeroTier status and config
  peers                                Show VL1 peers
  roots                                Show configured VL1 root servers
  addroot <identity> [IP/port]         Add VL1 root
  removeroot <identity|address>        Remove VL1 root server
  identity <command> [args]            Identity management commands
    new [c25519|p384]                  Create identity (including secret)
    getpublic <identity>               Extract only public part of identity
    validate <identity>                Locally validate an identity
    sign <identity> <file>             Sign a file with an identity's key
    verify <identity> <file> <sig>     Verify a signature
  networks                             List joined VL2 virtual networks
  network <network ID>                 Show verbose network info
  join <network ID>                    Join a virtual network
  leave <network ID>                   Leave a virtual network
  set <network ID> <option> <value>    Set a network local config option
    manageips <boolean>                Is IP management allowed?
    manageroutes <boolean>             Is route management allowed?
    globalips <boolean>                Allow assignment of global IPs?
    globalroutes <boolean>             Can global IP space routes be set?
    defaultroute <boolean>             Can default route be overridden?
  set <local config option> <value>    Set a local configuration option
    phy <IP/bits> blacklist <boolean>  Set or clear blacklist for CIDR
    phy <IP/bits> trust <path ID/0>    Set or clear trusted path ID for CIDR
    virt <address> try <IP/port> [...] Set explicit IPs for reaching a peer
    port <port>                        Set primary local port for VL1 P2P
    secondaryport <port/0>             Set or disable secondary VL1 P2P port
    tertiaryport <port/0>              Set or disable tertiary VL1 P2P port
    portsearch <boolean>               Set or disable port search on startup
    portmapping <boolean>              Set or disable use of uPnP/NAT-PMP

Most commands require a secret token to permit control of a running ZeroTier
service. The CLI will automatically try to read this token from the
authtoken.secret file in the service's working directory and then from a
file called .zerotierauth in the user's home directory. The -t option can be
used to explicitly specify a location.`)
	fmt.Println()
}
