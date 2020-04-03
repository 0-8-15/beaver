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

#ifndef ZT_CONSTANTS_HPP
#define ZT_CONSTANTS_HPP

#include "../include/ZeroTierCore.h"
#include "OS.hpp"

#if __has_include("version.h")
#include "version.h"
#else /* dummy values for use inside IDEs, etc. */
#define ZEROTIER_VERSION_MAJOR 255
#define ZEROTIER_VERSION_MINOR 255
#define ZEROTIER_VERSION_REVISION 255
#define ZEROTIER_VERSION_BUILD 255
#endif

/**
 * Length of a ZeroTier address in bytes
 */
#define ZT_ADDRESS_LENGTH 5

/**
 * Addresses beginning with this byte are reserved for the joy of in-band signaling
 */
#define ZT_ADDRESS_RESERVED_PREFIX 0xff

/**
 * Bit mask for addresses against a uint64_t
 */
#define ZT_ADDRESS_MASK 0xffffffffffULL

/**
 * Maximum DNS or URL name size for an Endpoint (set so that max marshaled endpoint size is 64 bytes)
 */
#define ZT_ENDPOINT_MAX_NAME_SIZE 61

/**
 * Size of an identity hash (SHA384) in bytes
 */
#define ZT_IDENTITY_HASH_SIZE 48

/**
 * Default virtual network MTU (not physical)
 */
#define ZT_DEFAULT_MTU 2800

/**
 * Maximum number of packet fragments we'll support (11 is the maximum that will fit in a Buf)
 */
#define ZT_MAX_PACKET_FRAGMENTS 11

/**
 * Anti-DOS limit on the maximum incoming fragments per path
 */
#define ZT_MAX_INCOMING_FRAGMENTS_PER_PATH 32

/**
 * Sanity limit on the maximum size of a network config object
 */
#define ZT_MAX_NETWORK_CONFIG_BYTES 131072

/**
 * Length of peer shared secrets (256-bit, do not change)
 */
#define ZT_PEER_SECRET_KEY_LENGTH 32

/**
 * Maximum delay between timer task checks
 */
#define ZT_MAX_TIMER_TASK_INTERVAL 1000

/**
 * Interval between steps or stages in multi-stage NAT traversal operations.
 *
 * This is for example the interval between initial firewall openers and real packets
 * for two-phase IPv4 hole punch.
 */
#define ZT_NAT_TRAVERSAL_INTERVAL 200

/**
 * How often most internal cleanup and housekeeping tasks are performed
 */
#define ZT_HOUSEKEEPING_PERIOD 120000

/**
 * How often network housekeeping is performed
 *
 * Note that this affects how frequently we re-request network configurations
 * from network controllers if we haven't received one yet.
 */
#define ZT_NETWORK_HOUSEKEEPING_PERIOD 30000

/**
 * Delay between WHOIS retries in ms
 */
#define ZT_WHOIS_RETRY_DELAY 500

/**
 * Maximum number of ZT hops allowed (this is not IP hops/TTL)
 *
 * The protocol allows up to 7, but we limit it to something smaller.
 */
#define ZT_RELAY_MAX_HOPS 4

/**
 * Period between keepalives sent to paths if no other traffic has been sent
 */
#define ZT_PATH_KEEPALIVE_PERIOD 20000

/**
 * Timeout for path alive-ness (measured from last receive)
 */
#define ZT_PATH_ALIVE_TIMEOUT ((ZT_PATH_KEEPALIVE_PERIOD * 2) + 5000)

/**
 * Delay between calls to the pulse() method in Peer for each peer
 */
#define ZT_PEER_PULSE_INTERVAL ZT_PATH_KEEPALIVE_PERIOD

/**
 * Minimum interval between HELLOs to peers.
 */
#define ZT_PEER_HELLO_INTERVAL 120000LL

/**
 * Global timeout for peers in milliseconds
 *
 * This is global as in "entire world," and this value is 30 days. In this
 * code the global timeout is used to determine when to ignore cached
 * peers and their identity<>address mappings.
 */
#define ZT_PEER_GLOBAL_TIMEOUT 2592000000LL

/**
 * Maximum interval between sort/prioritize of paths for a peer
 */
#define ZT_PEER_PRIORITIZE_PATHS_INTERVAL 5000

/**
 * Delay between requests for updated network autoconf information
 *
 * Don't lengthen this as it affects things like QoS / uptime monitoring
 * via ZeroTier Central. This is the heartbeat, basically.
 */
#define ZT_NETWORK_AUTOCONF_DELAY 60000

/**
 * Sanity limit on maximum bridge routes
 *
 * If the number of bridge routes exceeds this, we cull routes from the
 * bridges with the most MACs behind them until it doesn't. This is a
 * sanity limit to prevent memory-filling DOS attacks, nothing more. No
 * physical LAN has anywhere even close to this many nodes. Note that this
 * does not limit the size of ZT virtual LANs, only bridge routing.
 */
#define ZT_MAX_BRIDGE_ROUTES 16777216

/**
 * If there is no known L2 bridging route, spam to up to this many active bridges
 */
#define ZT_MAX_BRIDGE_SPAM 32

/**
 * Interval between attempts to make a direct connection if one does not exist
 */
#define ZT_DIRECT_CONNECT_ATTEMPT_INTERVAL 30000

/**
 * Maximum number of paths per IP scope (e.g. global, link-local) and family (e.g. v4/v6)
 */
#define ZT_PUSH_DIRECT_PATHS_MAX_PER_SCOPE_AND_FAMILY 4

/**
 * WHOIS rate limit (we allow these to be pretty fast)
 */
#define ZT_PEER_WHOIS_RATE_LIMIT 100

/**
 * General rate limit for other kinds of rate-limited packets (HELLO, credential request, etc.) both inbound and outbound
 */
#define ZT_PEER_GENERAL_RATE_LIMIT 500

/**
 * Don't do expensive identity validation more often than this
 *
 * IPv4 and IPv6 address prefixes are hashed down to 14-bit (0-16383) integers
 * using the first 24 bits for IPv4 or the first 48 bits for IPv6. These are
 * then rate limited to one identity validation per this often milliseconds.
 */
#if (defined(__amd64) || defined(__amd64__) || defined(__x86_64) || defined(__x86_64__) || defined(__AMD64) || defined(__AMD64__) || defined(_M_X64) || defined(_M_AMD64))
// AMD64 machines can do anywhere from one every 50ms to one every 10ms. This provides plenty of margin.
#define ZT_IDENTITY_VALIDATION_SOURCE_RATE_LIMIT 2000
#else
#if (defined(__i386__) || defined(__i486__) || defined(__i586__) || defined(__i686__) || defined(_M_IX86) || defined(_X86_) || defined(__I86__))
// 32-bit Intel machines usually average about one every 100ms
#define ZT_IDENTITY_VALIDATION_SOURCE_RATE_LIMIT 5000
#else
// This provides a safe margin for ARM, MIPS, etc. that usually average one every 250-400ms
#define ZT_IDENTITY_VALIDATION_SOURCE_RATE_LIMIT 10000
#endif
#endif

/**
 * Size of a buffer to store either a C25519 or an ECC P-384 signature
 *
 * This must be large enough to hold all signature types.
 */
#define ZT_SIGNATURE_BUFFER_SIZE 96

// Internal cryptographic algorithm IDs (these match relevant identity types)
#define ZT_CRYPTO_ALG_C25519 0
#define ZT_CRYPTO_ALG_P384 1

/* Ethernet frame types that might be relevant to us */
#define ZT_ETHERTYPE_IPV4 0x0800
#define ZT_ETHERTYPE_ARP 0x0806
#define ZT_ETHERTYPE_IPV6 0x86dd

#endif
