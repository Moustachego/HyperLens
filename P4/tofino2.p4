/***************************************************************
 * Name:      tofino2.p4
 * Purpose:   Show the basic forwarding function of Tofino2
 * Author:    weijzh (weijzh@pcl.ac.cn)
 * Created:   2025-10-23
 * Modified:  2025-11-25
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
    bit<9> Group_id;           // GID1 from Stage-1 (primary)
    bit<9> Group_id_secondary; // Secondary GID from Stage-1 (e.g., for backup path)
    bit<9> Group_id2;          // GID2 from Stage-2
    bit<11> src_quotient;      // Source port quotient (high 11 bits)
    bit<11> dst_quotient;      // Dest port quotient (high 11 bits)
    bit<5> src_remainder;      // Source port remainder (low 5 bits)
    bit<5> dst_remainder;      // Dest port remainder (low 5 bits)
    bit<32> src_bitmap;        // Source port bitmap from SRAM
    bit<32> dst_bitmap;        // Dest port bitmap from SRAM
    bool ip_table_hit;      // IP table hit flag
    bool src_tcam_hit;         // SRC_TCAM hit flag
    bool src_sram_hit;         // SRC_SRAM hit flag
    bool dst_tcam_hit;         // DST_TCAM hit flag
    bool dst_sram_hit;         // DST_SRAM hit flag
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
        
        // Initialize metadata
        ig_md.Group_id = 0;
        ig_md.Group_id_secondary = 0;
        ig_md.Group_id2 = 0;
        ig_md.src_quotient = 0;
        ig_md.dst_quotient = 0;
        ig_md.src_remainder = 0;
        ig_md.dst_remainder = 0;
        ig_md.src_bitmap = 0;
        ig_md.dst_bitmap = 0;
        ig_md.src_tcam_hit = false;
        ig_md.src_sram_hit = false;
        ig_md.dst_tcam_hit = false;
        ig_md.dst_sram_hit = false;
        
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

    // ========== Common Actions ==========
    action drop() {
        ig_dprsr_md.drop_ctl = 0x1;
    }

    action forward(bit<9> port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action nop() {
    }

    // ========== Stage-1: IP Table ==========
    action set_gid1(bit<9> gid1, bit<9> gid_secondary) {              
        ig_md.Group_id = gid1;
        ig_md.Group_id_secondary = gid_secondary;
        ig_md.ip_table_hit = true;
    }

    table ip_table {
        key = {
            vrf : exact;
            p.ipv4.src : ternary;
            p.ipv4.dst : ternary;
            p.ipv4.proto : exact;
        }
        actions = {
            set_gid1;
            drop;
        }
        default_action = drop;
        size = 1024;
    }

    // ========== Stage-2: SRC Port Matching ==========
    
    // SRC_TCAM (Primary GID): Ternary matching for sparse port rules
    action set_gid2_from_tcam(bit<9> gid2) {
        ig_md.Group_id2 = gid2;
        ig_md.src_tcam_hit = true;
    }

    table src_tcam_table {
        key = {
            ig_md.Group_id : exact;
            p.udp.sport : ternary;  // 16-bit ternary for wildcards
        }
        actions = {
            set_gid2_from_tcam;
            drop;
        }
        default_action = drop;
        size = 2048;
    }

    // SRC_SRAM: Exact matching with bitmap for dense port sets
    action set_src_bitmap(bit<32> bitmap, bit<9> gid2) {
        ig_md.src_bitmap = bitmap;
        ig_md.Group_id2 = gid2;
        ig_md.src_sram_hit = true;
    }

    table src_sram_table {
        key = {
            ig_md.Group_id : exact;
            ig_md.src_quotient : exact;  // High 11 bits of port
        }
        actions = {
            set_src_bitmap;
            drop;
        }
        default_action = drop;
        size = 4096;
    }

    // SRC_TCAM (Secondary GID): For fallback matching
    action set_gid2_from_tcam_secondary(bit<9> gid2) {
        ig_md.Group_id2 = gid2;
        ig_md.src_tcam_hit = true;
    }

    table src_tcam_table_secondary {
        key = {
            ig_md.Group_id_secondary : exact;
            p.udp.sport : ternary;
        }
        actions = {
            set_gid2_from_tcam_secondary;
            nop;
        }
        default_action = nop;
        size = 2048;
    }

    // SRC_SRAM (Secondary GID): For fallback matching
    action set_src_bitmap_secondary(bit<32> bitmap, bit<9> gid2) {
        ig_md.src_bitmap = bitmap;
        ig_md.Group_id2 = gid2;
        ig_md.src_sram_hit = true;
    }

    table src_sram_table_secondary {
        key = {
            ig_md.Group_id_secondary : exact;
            ig_md.src_quotient : exact;
        }
        actions = {
            set_src_bitmap_secondary;
            nop;
        }
        default_action = nop;
        size = 4096;
    }

    // ========== Stage-3: DST Port Matching ==========
    
    // DST_TCAM: Ternary matching for sparse port rules
    action set_action_from_tcam(bit<9> egress_port) {
        ig_tm_md.ucast_egress_port = egress_port;   // this should be action value
    }

    table dst_tcam_table {
        key = {
            ig_md.Group_id2 : exact;
            p.udp.dport : ternary;  // 16-bit ternary for wildcards
        }
        actions = {
            set_action_from_tcam;
            drop;
        }
        default_action = drop;
        size = 2048;
    }

    // DST_SRAM: Exact matching with bitmap for dense port sets
    action set_dst_bitmap(bit<32> bitmap, bit<9> egress_port) {
        ig_md.dst_bitmap = bitmap;
        ig_tm_md.ucast_egress_port = egress_port;      
    }

    table dst_sram_table {
        key = {
            ig_md.Group_id2 : exact;
            ig_md.dst_quotient : exact;  // High 11 bits of port
        }
        actions = {
            set_dst_bitmap;
            drop;
        }
        default_action = drop;
        size = 4096;
    }

    // ========== Apply Block ==========
    apply {
        vrf = 16w0;
        
        // Stage-1: IP + Protocol Matching
        if (ip_table.apply().hit) {
            
            // Calculate port quotient for SRAM lookup
            ig_md.src_quotient = p.udp.sport[15:5];  // High 11 bits
            ig_md.dst_quotient = p.udp.dport[15:5];

            // Stage-2: SRC Port Matching (Parallel check primary and secondary GID)
            bool src_tcam_match = src_tcam_table.apply().hit;
            bool src_sram_match = src_sram_table.apply().hit;
            bool src_match_primary = src_tcam_match || src_sram_match;
            
            // Try secondary GID tables if primary fails (轮询机制)
            bool src_match_secondary = false;
            if (!src_match_primary && ig_md.Group_id_secondary != 511) {
                bool src_tcam_match_sec = src_tcam_table_secondary.apply().hit;
                bool src_sram_match_sec = src_sram_table_secondary.apply().hit;
                if (src_tcam_match_sec || src_sram_match_sec) {
                    src_match_secondary = true;
                }
            }
            
            bool src_match = src_match_primary || src_match_secondary;

            if (src_match) {
                // Stage-3: DST Port Matching (Parallel TCAM + SRAM)
                bool dst_tcam_match = dst_tcam_table.apply().hit;
                bool dst_sram_match = dst_sram_table.apply().hit;

                // Stage-3 Decision: Prefer TCAM, fallback to SRAM
                if (!dst_tcam_match && !dst_sram_match) {
                    drop();
                }
            } else {
                drop();
            }
        } else {
            drop();
        }
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