// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#include "size.p4"

#ifndef __DEFINE__
#define __DEFINE__

#define IP_VERSION_4 4

#define IP_VER_BITS 4
#define ETH_TYPE_BYTES 2
#define ETH_HDR_BYTES 14
#define IPV4_HDR_BYTES 20
#define UDP_HDR_BYTES 8
#define MAX_COMPONENTS 8

typedef bit<3>  fwd_type_t;
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> l4_port_t;
typedef bit<128> ipv6_addr_t;
typedef bit<12> vlan_id_t;

#if defined(__TARGET_TOFINO__)
@p4runtime_translation("tna/PortId_t", 32)
#endif
type bit<9> BasicPortId_t;

const bit<8> DEFAULT_APP_ID = 0;
const bit<9> CPU_PORT = 64;//inset CPU port

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_ID = 16w0x0812;
const ether_type_t ETHERTYPE_GEO = 16w0x8947;
const ether_type_t ETHERTYPE_MF = 16w0x27c0;
const ether_type_t ETHERTYPE_NDN = 16w0x8624;
const ether_type_t ETHERTYPE_FLEXIP = 16w0x3690;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;
const bit<16> ETHERTYPE_PACKET_OUT = 0xBF01;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;


typedef bit<4> geo_protocol_t;
const geo_protocol_t TYPE_geo_beacon = 1;
const geo_protocol_t TYPE_geo_gbc = 4;     
const geo_protocol_t TYPE_geo_tsb = 5; 

action nop() {
    NoAction();
}

#endif // __DEFINE__
