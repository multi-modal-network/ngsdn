// Copyright 2020-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#include <core.p4>
#include <tna.p4>

#include "./include/defines.p4"
#include "./include/size.p4"
#include "./include/headers.p4"
#include "./include/parsers.p4"
#include "./include/control/packetio.p4"
#include "./include/control/table0.p4"

control ingress (
    /* Basic.p4 */
    inout ingress_headers_t hdr,
    inout Basic_ingress_metadata_t Basic_md,
    /* TNA */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md) {

    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) geo_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) l2_counter;

    action drop() {
        ig_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }

    action to_cpu() {
        ig_tm_md.ucast_egress_port = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = (BasicPortId_t)ig_intr_md.ingress_port;
    }

    action icmp_switch(PortId_t port) {
        l2_counter.count();
        ig_tm_md.ucast_egress_port = port;
    }

    action icmp6_switch(PortId_t port) {
        l2_counter.count();
        ig_tm_md.ucast_egress_port = port;
    }

    action route_l3() {
        l2_counter.count();
        Basic_md.l3 = 1;
    }

    table ing_dmac {
        key = {
            hdr.ethernet.src_addr : ternary;
            hdr.ethernet.dst_addr : ternary;
            hdr.ethernet.ether_type : exact;
        }

        actions = {
            icmp_switch;
            icmp6_switch;
            route_l3;
        }
        size = 24;
        const default_action = route_l3;
        counters = l2_counter;
    }

    action geo_ucast_route(PortId_t dst_port) {
       ig_tm_md.ucast_egress_port = dst_port;
       geo_counter.count();
    }
    action geo_mcast_route(MulticastGroupId_t mgid1) {
       ig_tm_md.mcast_grp_a = mgid1;
       geo_counter.count();
    }
    action geo_to_cpu(){
       ig_tm_md.ucast_egress_port = CPU_PORT;
       hdr.packet_in.setValid();
       hdr.packet_in.ingress_port = (BasicPortId_t)ig_intr_md.ingress_port;
       geo_counter.count();
    }
    table routing_geo_table {
       key = {
           hdr.ethernet.ether_type: exact;
           hdr.gbc.geo_area_pos_lat: exact;
           hdr.gbc.geo_area_pos_lon: exact;
           hdr.gbc.disa: exact;
           hdr.gbc.disb: exact;
       }

       actions = {
           geo_ucast_route;
           geo_mcast_route;
           geo_to_cpu;
       }
       default_action = geo_to_cpu;
       counters = geo_counter;
       size = 1024;
    }

     PacketIoIngress() pkt_io;
    Table0() table0;
    apply {
        if(hdr.ethernet.ether_type == ETHERTYPE_GEO){
            routing_geo_table.apply();
        }
        pkt_io.apply(hdr, Basic_md, ig_intr_md, ig_tm_md, ig_dprsr_md);
        table0.apply(hdr, Basic_md, ig_intr_md, ig_tm_md, ig_dprsr_md);
        ig_tm_md.bypass_egress = 1w1;
    }
}

control egress (
    /* Basic.p4 */
    inout egress_headers_t hdr,
    inout Basic_egress_metadata_t Basic_md,
    /* TNA */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md) {

    apply {
    }
}

Pipeline(
    BasicIngressParser(),
    ingress(),
    BasicIngressDeparser(),
    BasicEgressParser(),
    egress(),
    BasicEgressDeparser()
) pipe;

Switch(pipe) main;