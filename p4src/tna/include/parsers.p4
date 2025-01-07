// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#ifndef __PARSER__
#define __PARSER__

#include "../../shared/header.p4"
#include "../../shared/define.p4"

parser BasicIngressParser (packet_in  pkt,
    /* Basic.p4 */
    out ingress_headers_t               hdr,
    out Basic_ingress_metadata_t      Basic_md,
    /* TNA */
    out ingress_intrinsic_metadata_t   ig_intr_md) {
    Checksum() ipv4_checksum;

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        Basic_md.bridged.setValid();
        Basic_md.bridged.base.ig_port = ig_intr_md.ingress_port;
        Basic_md.egress_port_set = false;
        transition select(ig_intr_md.ingress_port){
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        pkt.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_IPV6 : parse_ipv6;
            ETHERTYPE_GEO  : parse_geo;
            ETHERTYPE_MF   : parse_mf;
            ETHERTYPE_NDN  : parse_ndn;
            ETHERTYPE_ID   : parse_id;
            ETHERTYPE_FLEXIP: parse_flexip;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }

        // NDN
    state parse_ndn {
        pkt.extract(hdr.ndn.ndn_prefix);
        transition parse_ndn_name;
    }

    state parse_ndn_name {
        pkt.extract(hdr.ndn.name_tlv.ndn_tlv_prefix);
        Basic_md.name_tlv_length = hdr.ndn.name_tlv.ndn_tlv_prefix.length;
        transition parse_ndn_name_components;
    }

    // state parse_ndn_name_components {
    //     pkt.extract(hdr.ndn.name_tlv.components.next);
    //     //ig_md.name_tlv_length = ig_md.name_tlv_length - 2 - hdr.ndn.name_tlv.components.last.length;
    //     transition select(ig_md.name_tlv_length) {
    //         0: parse_ndn_metainfo;
    //         default: parse_ndn_name_components;
    //     }
    // }

    state parse_ndn_name_components {
        pkt.extract(hdr.ndn.name_tlv.components.next);
        transition select(hdr.ndn.name_tlv.components.last.end) {
            0: parse_ndn_name_components;
            1: parse_ndn_metainfo;
        }
    }

    state parse_ndn_metainfo {
        pkt.extract(hdr.ndn.metaInfo_tlv.ndn_tlv_prefix);
        pkt.extract(hdr.ndn.metaInfo_tlv.content_type_tlv);
        pkt.extract(hdr.ndn.metaInfo_tlv.freshness_period_tlv);
        pkt.extract(hdr.ndn.metaInfo_tlv.final_block_id_tlv);
        transition parse_ndn_content;
    }

    state parse_ndn_content {
        pkt.extract(hdr.ndn.content_tlv);
        transition accept;
    }

    // ID
    state parse_id {
        pkt.extract(hdr.id);
        transition accept;
    }

    // IPv6
    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition accept;
    }

    // MF
    state parse_mf {
        pkt.extract(hdr.mf);
        transition accept;
    }

    // GEO
    state parse_geo {
        pkt.extract(hdr.geo);
        transition select(hdr.geo.ht) { //
            TYPE_geo_beacon: parse_beacon; //0x01
            TYPE_geo_gbc: parse_gbc;       //0x04
            default: accept;
        }
    }

    
    state parse_beacon{
        pkt.extract(hdr.beacon);
        transition accept;
    }

    state parse_gbc{
        pkt.extract(hdr.gbc);
        transition accept;
    }

    state parse_flexip {
        pkt.extract(hdr.flexip);
        transition accept;
    }

}

control BasicIngressDeparser(packet_out pkt,
    /* Basic.p4 */
    inout ingress_headers_t hdr,
    in Basic_ingress_metadata_t Basic_md,
    /* TNA */
    in ingress_intrinsic_metadata_for_deparser_t ig_intr_md_for_dprsr) {

    apply {
        pkt.emit(hdr);
    }
}

parser BasicEgressParser (packet_in pkt,
    /* Basic.p4 */
    out egress_headers_t hdr,
    out Basic_egress_metadata_t Basic_md,
    /* TNA */
    out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }

}


control BasicEgressDeparser(packet_out pkt,
    /* Basic.p4 */
    inout egress_headers_t hdr,
    in Basic_egress_metadata_t Basic_md,
    /* TNA */
    in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
    Checksum() ipv4_checksum;
    apply {
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        }
        pkt.emit(hdr);
    }
}

#endif // __PARSER__
