import os
import itertools

# Define the modalities and their components
modalities = {
    'IP': {
        'counters': ['ipv4_counter', 'ipv6_counter'],
        'tables': ['routing_v4_table', 'routing_v6_table'],
        'if_condition': {
            'ETHERTYPE_IPV4': ['routing_v4_table'],
            'ETHERTYPE_IPV6': ['routing_v6_table']
        }
    },
    'ID': {
        'counters': ['id_counter'],
        'tables': ['routing_id_table'],
        'if_condition': ['ETHERTYPE_ID']
    },
    'GEO': {
        'counters': ['geo_counter'],
        'tables': ['routing_geo_table'],
        'if_condition': ['ETHERTYPE_GEO']
    },
    'MF': {
        'counters': ['mf_counter'],
        'tables': ['routing_mf_table'],
        'if_condition': ['ETHERTYPE_MF']
    },
    'NDN': {
        'counters': ['ndn_counter'],
        'tables': ['routing_ndn_table'],
        'if_condition': ['ETHERTYPE_NDN']
    },
    'FLEXIP': {
        'counters': ['flexip_counter'],
        'tables': ['routing_flexip_table'],
        'if_condition': ['ETHERTYPE_FLEXIP']
    }
}

# Common components that should always be included
common_components = {
    'counters': ['l2_counter'],
    'tables': ['ing_dmac'],
    'actions': ['drop', 'to_cpu', 'icmp_switch', 'icmp6_switch', 'route_l3']
}

def generate_p4_file(combination):
    # Generate the filename
    filename = f"tofino_{'_'.join(sorted(combination))}.p4"
    
    # Start with the template header
    content = """// Copyright 2020-present Open Networking Foundation
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
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md) {\n\n"""

    # Add counters
    counters = common_components['counters'].copy()
    for mod in combination:
        counters.extend(modalities[mod]['counters'])
    
    for counter in sorted(set(counters)):
        content += f"    DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) {counter};\n"

    # Add common actions
    content += """
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
    }\n\n"""

    # Add common table (ing_dmac)
    content += """    table ing_dmac {
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
    }\n\n"""

    # Add modality-specific tables and actions
    for mod in combination:
        if mod == 'IP':
            content += """    action set_next_v4_hop(PortId_t dst_port) {
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
    }\n\n"""
        
        elif mod == 'ID':
            content += """    action set_next_id_hop(PortId_t dst_port){
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
    }\n\n"""

        elif mod == "NDN":
            content += """    action set_next_ndn_hop(PortId_t dst_port) {
       ig_tm_md.ucast_egress_port = dst_port;
       ndn_counter.count();
    }
    action ndn_to_cpu(){
       ig_tm_md.ucast_egress_port = CPU_PORT;
       hdr.packet_in.setValid();
       hdr.packet_in.ingress_port = (BasicPortId_t)ig_intr_md.ingress_port;
       ndn_counter.count();
    }
    table routing_ndn_table {
       key = {
           hdr.ethernet.ether_type: exact;
           hdr.ndn.ndn_prefix.code: exact;
           hdr.ndn.name_tlv.components[0].value: exact;
           hdr.ndn.name_tlv.components[1].value: exact;
           hdr.ndn.content_tlv.value: exact;
       }

       actions = {
           set_next_ndn_hop;
           ndn_to_cpu;
       }
       default_action = ndn_to_cpu;
       counters = ndn_counter;
       size = 1024;
    }\n\n"""

        elif mod == "GEO":
            content += """    action geo_ucast_route(PortId_t dst_port) {
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
    }\n\n """

        elif mod == "MF":
            content += """    action set_next_mf_hop(PortId_t dst_port) {
      ig_tm_md.ucast_egress_port = dst_port;
      mf_counter.count();
    }
    action mf_to_cpu(){
      ig_tm_md.ucast_egress_port = CPU_PORT;
      hdr.packet_in.setValid();
      hdr.packet_in.ingress_port = (BasicPortId_t)ig_intr_md.ingress_port;
      mf_counter.count();
    }
    table routing_mf_table {
      key = {
          hdr.ethernet.ether_type: exact;
          hdr.mf.src_guid: exact;
          hdr.mf.dst_guid : exact;
      }

      actions = {
          set_next_mf_hop;
          mf_to_cpu;
      }
      default_action = mf_to_cpu;
      counters = mf_counter;
      size = 1024;
    }\n\n """

        elif mod == "FLEXIP":
            content += """    action set_next_flexip_hop(PortId_t dst_port) {
      ig_tm_md.ucast_egress_port = dst_port;
      flexip_counter.count();
    }
    action flexip_to_cpu(){
      ig_tm_md.ucast_egress_port = CPU_PORT;
      hdr.packet_in.setValid();
      hdr.packet_in.ingress_port = (BasicPortId_t)ig_intr_md.ingress_port;
      flexip_counter.count();
    }
    table routing_flexip_table {
      key = {
          hdr.ethernet.ether_type: exact;
          hdr.flexip.src_format: exact;
          hdr.flexip.dst_format: exact;
          hdr.flexip.src_addr: exact;
          hdr.flexip.dst_addr: exact;
      }
      actions = {
          set_next_flexip_hop;
          flexip_to_cpu;
      }
      default_action = flexip_to_cpu;
      counters = flexip_counter;
      size = 1024;
    }\n\n """

        # Add similar blocks for GEO, MF, NDN, FLEXIP...
        # [Rest of the modality-specific code would go here...]

    # Add the apply block
    content += """    PacketIoIngress() pkt_io;
    Table0() table0;
    apply {\n"""
    
    for mod in combination:
        if_conditions = modalities[mod]['if_condition']
        if isinstance(if_conditions, dict):  # 处理IP等复杂条件
            for condition, tables in if_conditions.items():
                content += f"        if(hdr.ethernet.ether_type == {condition}){{\n"
                for table in tables:
                    content += f"            {table}.apply();\n"
                content += "        }\n"
        else:  # 处理简单条件
            for condition in if_conditions:
                content += f"        if(hdr.ethernet.ether_type == {condition}){{\n"
                for table in modalities[mod]['tables']:
                    content += f"            {table}.apply();\n"
                content += "        }\n"
    
    content += """        pkt_io.apply(hdr, Basic_md, ig_intr_md, ig_tm_md, ig_dprsr_md);
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

Switch(pipe) main;"""

    # Write to file
    with open(filename, 'w') as f:
        f.write(content)

modality_order = ['IP', 'ID', 'GEO', 'MF', 'NDN', 'FLEXIP']

def main():
    # Create output directory if it doesn't exist
    if not os.path.exists('generated'):
        os.makedirs('generated')
    os.chdir('generated')
    
    # Generate all non-empty combinations (1-6 modalities)
    for r in range(1, 7):
        for combo in itertools.combinations(modality_order, r):
            generate_p4_file(combo)
    
    print("Generated 63 P4 files in the 'generated' directory.")

if __name__ == "__main__":
    main()