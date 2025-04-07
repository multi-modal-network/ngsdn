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

    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) id_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ipv4_counter;
    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) ipv6_counter;
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

    action set_next_v4_hop(PortId_t dst_port) {
        ig_tm_md.ucast_egress_port = dst_port;
        ipv4_counter.count();
    }
    action v4_to_cpu(){
        ig_tm_md.ucast_egress_port = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = (BasicPortId_t)ig_intr_md.ingress_port;
        ipv4_counter.count();
    }
    table routing_v4_table {
        key = {
            hdr.ethernet.ether_type: exact;
            hdr.ipv4.src_addr: exact;
            hdr.ipv4.dst_addr: exact;
        }

        actions = {
            set_next_v4_hop;
            v4_to_cpu;
        }
        default_action  = v4_to_cpu;
        counters = ipv4_counter;
        size = 1024;
    }

    action set_next_v6_hop(PortId_t dst_port) {
        ig_tm_md.ucast_egress_port = dst_port;
        ipv6_counter.count();
    }
    action v6_to_cpu(){
        ig_tm_md.ucast_egress_port = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = (BasicPortId_t)ig_intr_md.ingress_port;
        ipv6_counter.count();
    }
    table routing_v6_table {
        key = {
            hdr.ethernet.ether_type: exact;
            hdr.ipv6.src_addr: exact;
            hdr.ipv6.dst_addr: exact;
        }

        actions = {
            set_next_v6_hop;
            v6_to_cpu;
        }
        default_action = v6_to_cpu;
        counters = ipv6_counter;
        size = 1024;
    }

    action set_next_id_hop(PortId_t dst_port){
        ig_tm_md.ucast_egress_port = dst_port;
        id_counter.count();
    }
    action id_to_cpu(){
        ig_tm_md.ucast_egress_port = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = (BasicPortId_t)ig_intr_md.ingress_port;
        id_counter.count();
    }
    table routing_id_table {
        key = {
            hdr.ethernet.ether_type: exact;
            hdr.id.src_identity: exact;
            hdr.id.dst_identity: exact;
        }
        actions = {
            set_next_id_hop;
            id_to_cpu;
        }
        default_action = id_to_cpu;
        counters = id_counter;
        size = 1024;
    }

    PacketIoIngress() pkt_io;
    Table0() table0;
    apply {
        if(hdr.ethernet.ether_type == ETHERTYPE_IPV4){
            routing_v4_table.apply();
        }
        if(hdr.ethernet.ether_type == ETHERTYPE_IPV6){
            routing_v6_table.apply();
        }
        if(hdr.ethernet.ether_type == ETHERTYPE_ID){
            routing_id_table.apply();
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