/***************************************************************
 * Name:      tofino2.p4
 * Purpose:   Show the basic forwarding function of Tofino2
 * Author:    weijzh (weijzh@pcl.ac.cn)
 * Created:   2025-10-23
 * Copyright: weijzh (https://www.pcl.ac.cn)
 **************************************************************/

#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>

#else
#include <tna.p4>
#endif


// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------

typedef bit<48> MacAddress;
typedef bit<32> IPv4Address;

header ethernet_h {
    MacAddress dst;
    MacAddress src;
    bit<16> etherType; 
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> tos;
    bit<16> len;
    bit<16> id;
    bit<3> flags;
    bit<13> frag;
    bit<8> ttl;
    bit<8> proto;
    bit<16> chksum;
    IPv4Address src;
    IPv4Address dst; 
}

header tcp_h {
    bit<16> sport;
    bit<16> dport;
    bit<32> seq;
    bit<32> ack;
    bit<4> dataofs;
    bit<4> reserved;
    bit<8> flags;
    bit<16> window;
    bit<16> chksum;
    bit<16> urgptr; 
}

header udp_h {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> chksum; 
}


// ---------------------------------------------------------------------------
// struct
// ---------------------------------------------------------------------------

struct headers { 
    ethernet_h ethernet;
    ipv4_h ipv4;
    udp_h udp;
    tcp_h tcp;

}

// user defined metadata
struct user_metadata_t {
    bit<9> Group_id;
    // bit<16> lrm_id1;
    // bit<16> lrm_id2;
 }

struct eg_metadata_t {

}

// ---------------------------------------------------------------------------
// Ingress Parser
// ---------------------------------------------------------------------------

parser SwitchIngressParser(
        packet_in pkt,
        out headers p,
        out user_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(p.ethernet);

        transition select(p.ethernet.etherType) {
			0x800: parse_ip;
			default: accept;
		}
    }

	state parse_ip {
        pkt.extract(p.ipv4);

		transition select(p.ipv4.proto) {
            6: parse_tcp;
            17: parse_udp;
			default: accept;
		}
	}

    state parse_udp {
        pkt.extract(p.udp);
		transition select(p.udp.dport) {
			default: accept;
		}
	}

    state parse_tcp {
        pkt.extract(p.tcp);
        transition select(p.tcp.dport) {
            default: accept;
        }
    }

}

// ---------------------------------------------------------------------------
// Ingress
// ---------------------------------------------------------------------------

control SwitchIngress(
        inout headers p,
        inout user_metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
            
    bit<16> vrf;

    action drop() {
    ig_dprsr_md.drop_ctl = 0x1;  // 丢包
    }

    action get_coupling_info(bit<9> Group_id) {              
        ig_md.Group_id = Group_id;
    }

    table ip_table {
        key = {
            vrf : exact;
            p.ipv4.src : ternary;
            p.ipv4.dst : ternary;
            p.ipv4.proto : exact;
        }
        actions = {
            drop; 
            get_coupling_info;
        }
        default_action = drop;
        size = 1024; 

    }

    action forward(bit<9> port) {
        // 使用 ingress_tm metadata 设置 egress port
        ig_tm_md.ucast_egress_port = port;
    }

    table port_table {
    key = {
        ig_md.Group_id : exact;
        p.udp.sport   : exact;
        p.udp.dport   : exact;
    }
    actions = {
        forward;
        drop;
    }
    default_action = drop;
    size = 1024;
    }

    apply{
        vrf = 16w0;
        ip_table.apply();
        port_table.apply();
    }
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------

control SwitchIngressDeparser(
        packet_out pkt,
        inout headers p,
        in user_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    apply {
        pkt.emit(p);
    }
}

// ---------------------------------------------------------------------------
// Egress Parser
// ---------------------------------------------------------------------------

parser SwitchEgressParser(
        packet_in pkt,
        out headers p,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        pkt.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(p.ethernet);
        transition select(p.ethernet.etherType) {
			0x800: parse_ip;
			default: accept;
		}
    }

	state parse_ip {
        pkt.extract(p.ipv4);
        transition accept;
	}
}

// ---------------------------------------------------------------------------
// Egress
// ---------------------------------------------------------------------------

control SwitchEgress(
        /* User */
        inout headers p,
        inout eg_metadata_t meta,
        /* Intrinsic */
        in    egress_intrinsic_metadata_t eg_intr_md,
        in    egress_intrinsic_metadata_from_parser_t eg_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    
    apply {
        // p.ipv4.dst = eg_prsr_md.global_tstamp[31:0];
        // p.ethernet.src = eg_prsr_md.global_tstamp;
    }
}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------

control SwitchEgressDeparser(
        packet_out pkt,
        /* User */
        inout headers p,
        in eg_metadata_t meta,
        /* Intrinsic */
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
    apply {
        pkt.emit(p);
    }
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;