/***************************************************************
 * Name:      tofino2.p4
 * Purpose:   Show the basic forwarding function of Tofino2
 * Author:    weijzh (weijzh@pcl.ac.cn)
 * Created:   2025-10-23
 * Modified:  2026-03-23
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
#define GID2_WIDTH 14
typedef bit<GID2_WIDTH> gid2_t;

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
    // Stage 1: IP lookup result
    bit<16> Group_id;           // GID1 from ip_table
    bit<16> Group_id_secondary; // Backup GID from Stage-1 (unused currently)

    // Stage 2: SRC port lookup
    // GID2 width is shared with the controller's GID2_WIDTH.
    gid2_t Group_id2;          // Final GID2 from Stage-2 (consolidated, wildcard-capable)
    gid2_t src_gid2_from_tcam; // GID2 from SRC TCAM path
    gid2_t src_gid2_from_sram; // GID2 from SRC SRAM path

    // Stage 3: DST port lookup
    bit<9> five_tuple_action;   // Action from 5-tuple TCAM (for Path A)
    bit<9> dst_action_from_tcam;// Action from DST TCAM path
    bit<9> dst_action_from_sram;// Action from DST SRAM path

    // Normalized L4 ports
    bit<16> l4_src_port;        // Normalized L4 src port (TCP/UDP)
    bit<16> l4_dst_port;        // Normalized L4 dst port (TCP/UDP)

    // Port quotient/remainder for SRAM bucket indexing
    bit<11> src_quotient;       // SrcPort / 32 (high 11 bits)
    bit<11> dst_quotient;       // DstPort / 32 (high 11 bits)
    bit<5> src_remainder;       // SrcPort % 32 (low 5 bits)
    bit<5> dst_remainder;       // DstPort % 32 (low 5 bits)

    // SRAM bitmaps (32-port blocks)
    bit<32> src_bitmap;         // Bitmap from SRC SRAM bucket
    bit<32> dst_bitmap;         // Bitmap from DST SRAM bucket

    // Bucket hit vs bitmap hit distinction
    bool src_sram_bucket_hit;   // SRC SRAM bucket found
    bool src_sram_bitmap_hit;   // SRC SRAM bitmap bit = 1
    bit<1> src_bitmap_bit;      // Extracted bitmap bit for debug

    bool dst_sram_bucket_hit;   // DST SRAM bucket found
    bool dst_sram_bitmap_hit;   // DST SRAM bitmap bit = 1
    bit<1> dst_bitmap_bit;      // Extracted bitmap bit for debug

    // Hit flags for path tracking
    bool ip_table_hit;          // IP table (Stage 1) hit flag
    bool src_tcam_hit;          // SRC TCAM path hit flag
    bool src_sram_hit;          // SRC SRAM path bucket hit flag
    bool dst_tcam_hit;          // DST TCAM path hit flag
    bool dst_sram_hit;          // DST SRAM path bucket hit flag
    bool five_tuple_hit;        // 5-tuple TCAM hit flag (Path A)

    // Debug: drop reason code
    bit<8> drop_reason;         // 0=success, other=drop reason
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

        // Initialize metadata (parser stage)
        ig_md.Group_id = 0;
        ig_md.Group_id_secondary = 0;
        ig_md.Group_id2 = 0;
        ig_md.five_tuple_action = 0;
        ig_md.src_gid2_from_tcam = 0;
        ig_md.src_gid2_from_sram = 0;
        ig_md.dst_action_from_tcam = 0;
        ig_md.dst_action_from_sram = 0;
        ig_md.l4_src_port = 0;
        ig_md.l4_dst_port = 0;
        ig_md.src_quotient = 0;
        ig_md.dst_quotient = 0;
        ig_md.src_remainder = 0;
        ig_md.dst_remainder = 0;
        ig_md.src_bitmap = 0;
        ig_md.dst_bitmap = 0;
        ig_md.src_sram_bucket_hit = false;
        ig_md.src_sram_bitmap_hit = false;
        ig_md.src_bitmap_bit = 0;
        ig_md.dst_sram_bucket_hit = false;
        ig_md.dst_sram_bitmap_hit = false;
        ig_md.dst_bitmap_bit = 0;
        ig_md.ip_table_hit = false;
        ig_md.src_tcam_hit = false;
        ig_md.src_sram_hit = false;
        ig_md.dst_tcam_hit = false;
        ig_md.dst_sram_hit = false;
        ig_md.five_tuple_hit = false;
        ig_md.drop_reason = 0;

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

    // Throughput Test Mode: If true, no packet drop, all forward to port 2/0
    const bool THROUGHPUT_TEST_MODE = true;

    bit<16> vrf;

    // ========== Common Actions ==========
    action drop() {
        ig_dprsr_md.drop_ctl = 0x1;
    }

    action forward(bit<9> port) {
        ig_tm_md.ucast_egress_port = port;
    }

    // Test mode: force all IPv4 packets to physical port 2/0 (dev_port=144)
    action forward_to_port2() {
        ig_tm_md.ucast_egress_port = 9w144;
    }

    action nop() {
    }

    // ========== Parallel Path: 5-Tuple TCAM ==========
    action set_five_tuple_result(bit<9> egress_port) {
        ig_md.five_tuple_action = egress_port;
        ig_md.five_tuple_hit = true;
    }

    table five_tuple_tcam {
        key = {
            vrf : exact;
            p.ipv4.src : ternary;
            p.ipv4.dst : ternary;
            p.ipv4.proto : exact;
            ig_md.l4_src_port : ternary;
            ig_md.l4_dst_port : ternary;
        }
        actions = {
            forward_to_port2;
            nop;
        }
        default_action = nop;
        size = 23;
    }

    // ========== Stage-1: IP Table ==========
    action set_gid1(bit<16> gid1) {
        ig_md.Group_id = gid1;
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
            nop;
        }
        default_action = nop;
        size = 1291;
    }

    // ========== Stage-2: SRC Port Matching ==========

    // SRC_TCAM: Store result in src_gid2_from_tcam, not Group_id2 directly
    action set_src_gid2_from_tcam(gid2_t gid2) {
        ig_md.src_gid2_from_tcam = gid2;
        ig_md.src_tcam_hit = true;
    }

    table src_tcam_table {
        key = {
            ig_md.Group_id : exact;
            ig_md.l4_src_port : ternary;  // 16-bit ternary for wildcards
        }
        actions = {
            set_src_gid2_from_tcam;
            nop;
        }
        default_action = nop;
        size = 1291;
    }

    // SRC_SRAM: Only mark bucket hit, don't finalize Group_id2
    action set_src_sram_bucket(bit<32> bitmap, gid2_t gid2) {
        ig_md.src_bitmap = bitmap;
        ig_md.src_gid2_from_sram = gid2;
        ig_md.src_sram_bucket_hit = true;
    }

    table src_sram_table {
        key = {
            ig_md.Group_id : exact;
            ig_md.src_quotient : exact;  // High 11 bits of port
        }
        actions = {
            set_src_sram_bucket;
            nop;
        }
        default_action = nop;
        size = 1;
    }

    // ========== Stage-3: DST Port Matching ==========

    // DST_TCAM: Store result in dst_action_from_tcam, not egress_port directly
    action set_dst_action_from_tcam(bit<9> egress_port) {
        ig_md.dst_action_from_tcam = egress_port;
        ig_md.dst_tcam_hit = true;
    }

    table dst_tcam_table {
        key = {
            ig_md.Group_id2 : ternary;
            ig_md.l4_dst_port : ternary;  // 16-bit ternary for wildcards
        }
        actions = {
            set_dst_action_from_tcam;
            nop;
        }
        default_action = nop;
        size = 7230;
    }

    // DST_SRAM: Only mark bucket hit, don't finalize egress_port
    action set_dst_sram_bucket(bit<32> bitmap, bit<9> egress_port) {
        ig_md.dst_bitmap = bitmap;
        ig_md.dst_action_from_sram = egress_port;
        ig_md.dst_sram_bucket_hit = true;
    }

    table dst_sram_table {
        key = {
            ig_md.Group_id2 : exact;
            ig_md.dst_quotient : exact;  // High 11 bits of port
        }
        actions = {
            set_dst_sram_bucket;
            nop;
        }
        default_action = nop;
        size = 2266;
    }

    // ========== Stage-2b: SRC Bitmap Selector Actions ==========
    // These 32 actions are indexed by src_remainder (0-31)
    // Each action extracts the corresponding bit from src_bitmap

    action src_pick_bit_0()  { ig_md.src_bitmap_bit = ig_md.src_bitmap[0:0];  }
    action src_pick_bit_1()  { ig_md.src_bitmap_bit = ig_md.src_bitmap[1:1];  }
    action src_pick_bit_2()  { ig_md.src_bitmap_bit = ig_md.src_bitmap[2:2];  }
    action src_pick_bit_3()  { ig_md.src_bitmap_bit = ig_md.src_bitmap[3:3];  }
    action src_pick_bit_4()  { ig_md.src_bitmap_bit = ig_md.src_bitmap[4:4];  }
    action src_pick_bit_5()  { ig_md.src_bitmap_bit = ig_md.src_bitmap[5:5];  }
    action src_pick_bit_6()  { ig_md.src_bitmap_bit = ig_md.src_bitmap[6:6];  }
    action src_pick_bit_7()  { ig_md.src_bitmap_bit = ig_md.src_bitmap[7:7];  }
    action src_pick_bit_8()  { ig_md.src_bitmap_bit = ig_md.src_bitmap[8:8];  }
    action src_pick_bit_9()  { ig_md.src_bitmap_bit = ig_md.src_bitmap[9:9];  }
    action src_pick_bit_10() { ig_md.src_bitmap_bit = ig_md.src_bitmap[10:10]; }
    action src_pick_bit_11() { ig_md.src_bitmap_bit = ig_md.src_bitmap[11:11]; }
    action src_pick_bit_12() { ig_md.src_bitmap_bit = ig_md.src_bitmap[12:12]; }
    action src_pick_bit_13() { ig_md.src_bitmap_bit = ig_md.src_bitmap[13:13]; }
    action src_pick_bit_14() { ig_md.src_bitmap_bit = ig_md.src_bitmap[14:14]; }
    action src_pick_bit_15() { ig_md.src_bitmap_bit = ig_md.src_bitmap[15:15]; }
    action src_pick_bit_16() { ig_md.src_bitmap_bit = ig_md.src_bitmap[16:16]; }
    action src_pick_bit_17() { ig_md.src_bitmap_bit = ig_md.src_bitmap[17:17]; }
    action src_pick_bit_18() { ig_md.src_bitmap_bit = ig_md.src_bitmap[18:18]; }
    action src_pick_bit_19() { ig_md.src_bitmap_bit = ig_md.src_bitmap[19:19]; }
    action src_pick_bit_20() { ig_md.src_bitmap_bit = ig_md.src_bitmap[20:20]; }
    action src_pick_bit_21() { ig_md.src_bitmap_bit = ig_md.src_bitmap[21:21]; }
    action src_pick_bit_22() { ig_md.src_bitmap_bit = ig_md.src_bitmap[22:22]; }
    action src_pick_bit_23() { ig_md.src_bitmap_bit = ig_md.src_bitmap[23:23]; }
    action src_pick_bit_24() { ig_md.src_bitmap_bit = ig_md.src_bitmap[24:24]; }
    action src_pick_bit_25() { ig_md.src_bitmap_bit = ig_md.src_bitmap[25:25]; }
    action src_pick_bit_26() { ig_md.src_bitmap_bit = ig_md.src_bitmap[26:26]; }
    action src_pick_bit_27() { ig_md.src_bitmap_bit = ig_md.src_bitmap[27:27]; }
    action src_pick_bit_28() { ig_md.src_bitmap_bit = ig_md.src_bitmap[28:28]; }
    action src_pick_bit_29() { ig_md.src_bitmap_bit = ig_md.src_bitmap[29:29]; }
    action src_pick_bit_30() { ig_md.src_bitmap_bit = ig_md.src_bitmap[30:30]; }
    action src_pick_bit_31() { ig_md.src_bitmap_bit = ig_md.src_bitmap[31:31]; }

    table src_bitmap_select_table {
        key = {
            ig_md.src_remainder : exact;  // 5-bit exact match (0-31)
        }
        actions = {
            src_pick_bit_0;   src_pick_bit_1;   src_pick_bit_2;   src_pick_bit_3;
            src_pick_bit_4;   src_pick_bit_5;   src_pick_bit_6;   src_pick_bit_7;
            src_pick_bit_8;   src_pick_bit_9;   src_pick_bit_10;  src_pick_bit_11;
            src_pick_bit_12;  src_pick_bit_13;  src_pick_bit_14;  src_pick_bit_15;
            src_pick_bit_16;  src_pick_bit_17;  src_pick_bit_18;  src_pick_bit_19;
            src_pick_bit_20;  src_pick_bit_21;  src_pick_bit_22;  src_pick_bit_23;
            src_pick_bit_24;  src_pick_bit_25;  src_pick_bit_26;  src_pick_bit_27;
            src_pick_bit_28;  src_pick_bit_29;  src_pick_bit_30;  src_pick_bit_31;
        }
        const entries = {
            5w0  : src_pick_bit_0();
            5w1  : src_pick_bit_1();
            5w2  : src_pick_bit_2();
            5w3  : src_pick_bit_3();
            5w4  : src_pick_bit_4();
            5w5  : src_pick_bit_5();
            5w6  : src_pick_bit_6();
            5w7  : src_pick_bit_7();
            5w8  : src_pick_bit_8();
            5w9  : src_pick_bit_9();
            5w10 : src_pick_bit_10();
            5w11 : src_pick_bit_11();
            5w12 : src_pick_bit_12();
            5w13 : src_pick_bit_13();
            5w14 : src_pick_bit_14();
            5w15 : src_pick_bit_15();
            5w16 : src_pick_bit_16();
            5w17 : src_pick_bit_17();
            5w18 : src_pick_bit_18();
            5w19 : src_pick_bit_19();
            5w20 : src_pick_bit_20();
            5w21 : src_pick_bit_21();
            5w22 : src_pick_bit_22();
            5w23 : src_pick_bit_23();
            5w24 : src_pick_bit_24();
            5w25 : src_pick_bit_25();
            5w26 : src_pick_bit_26();
            5w27 : src_pick_bit_27();
            5w28 : src_pick_bit_28();
            5w29 : src_pick_bit_29();
            5w30 : src_pick_bit_30();
            5w31 : src_pick_bit_31();
        }
        size = 32;
    }

    // ========== Stage-3b: DST Bitmap Selector Actions ==========
    // These 32 actions are indexed by dst_remainder (0-31)
    // Each action extracts the corresponding bit from dst_bitmap

    action dst_pick_bit_0()  { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[0:0];  }
    action dst_pick_bit_1()  { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[1:1];  }
    action dst_pick_bit_2()  { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[2:2];  }
    action dst_pick_bit_3()  { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[3:3];  }
    action dst_pick_bit_4()  { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[4:4];  }
    action dst_pick_bit_5()  { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[5:5];  }
    action dst_pick_bit_6()  { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[6:6];  }
    action dst_pick_bit_7()  { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[7:7];  }
    action dst_pick_bit_8()  { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[8:8];  }
    action dst_pick_bit_9()  { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[9:9];  }
    action dst_pick_bit_10() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[10:10]; }
    action dst_pick_bit_11() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[11:11]; }
    action dst_pick_bit_12() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[12:12]; }
    action dst_pick_bit_13() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[13:13]; }
    action dst_pick_bit_14() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[14:14]; }
    action dst_pick_bit_15() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[15:15]; }
    action dst_pick_bit_16() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[16:16]; }
    action dst_pick_bit_17() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[17:17]; }
    action dst_pick_bit_18() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[18:18]; }
    action dst_pick_bit_19() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[19:19]; }
    action dst_pick_bit_20() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[20:20]; }
    action dst_pick_bit_21() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[21:21]; }
    action dst_pick_bit_22() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[22:22]; }
    action dst_pick_bit_23() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[23:23]; }
    action dst_pick_bit_24() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[24:24]; }
    action dst_pick_bit_25() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[25:25]; }
    action dst_pick_bit_26() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[26:26]; }
    action dst_pick_bit_27() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[27:27]; }
    action dst_pick_bit_28() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[28:28]; }
    action dst_pick_bit_29() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[29:29]; }
    action dst_pick_bit_30() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[30:30]; }
    action dst_pick_bit_31() { ig_md.dst_bitmap_bit = ig_md.dst_bitmap[31:31]; }

    table dst_bitmap_select_table {
        key = {
            ig_md.dst_remainder : exact;  // 5-bit exact match (0-31)
        }
        actions = {
            dst_pick_bit_0;   dst_pick_bit_1;   dst_pick_bit_2;   dst_pick_bit_3;
            dst_pick_bit_4;   dst_pick_bit_5;   dst_pick_bit_6;   dst_pick_bit_7;
            dst_pick_bit_8;   dst_pick_bit_9;   dst_pick_bit_10;  dst_pick_bit_11;
            dst_pick_bit_12;  dst_pick_bit_13;  dst_pick_bit_14;  dst_pick_bit_15;
            dst_pick_bit_16;  dst_pick_bit_17;  dst_pick_bit_18;  dst_pick_bit_19;
            dst_pick_bit_20;  dst_pick_bit_21;  dst_pick_bit_22;  dst_pick_bit_23;
            dst_pick_bit_24;  dst_pick_bit_25;  dst_pick_bit_26;  dst_pick_bit_27;
            dst_pick_bit_28;  dst_pick_bit_29;  dst_pick_bit_30;  dst_pick_bit_31;
        }
        const entries = {
            5w0  : dst_pick_bit_0();
            5w1  : dst_pick_bit_1();
            5w2  : dst_pick_bit_2();
            5w3  : dst_pick_bit_3();
            5w4  : dst_pick_bit_4();
            5w5  : dst_pick_bit_5();
            5w6  : dst_pick_bit_6();
            5w7  : dst_pick_bit_7();
            5w8  : dst_pick_bit_8();
            5w9  : dst_pick_bit_9();
            5w10 : dst_pick_bit_10();
            5w11 : dst_pick_bit_11();
            5w12 : dst_pick_bit_12();
            5w13 : dst_pick_bit_13();
            5w14 : dst_pick_bit_14();
            5w15 : dst_pick_bit_15();
            5w16 : dst_pick_bit_16();
            5w17 : dst_pick_bit_17();
            5w18 : dst_pick_bit_18();
            5w19 : dst_pick_bit_19();
            5w20 : dst_pick_bit_20();
            5w21 : dst_pick_bit_21();
            5w22 : dst_pick_bit_22();
            5w23 : dst_pick_bit_23();
            5w24 : dst_pick_bit_24();
            5w25 : dst_pick_bit_25();
            5w26 : dst_pick_bit_26();
            5w27 : dst_pick_bit_27();
            5w28 : dst_pick_bit_28();
            5w29 : dst_pick_bit_29();
            5w30 : dst_pick_bit_30();
            5w31 : dst_pick_bit_31();
        }
        size = 32;
    }

    // ========== Apply Block ==========
    apply {
        vrf = 16w0;

        // =====================================================================
        // Phase 1: Port Normalization
        // =====================================================================
        // Normalize TCP/UDP ports into shared metadata fields
        if (p.tcp.isValid()) {
            ig_md.l4_src_port = p.tcp.sport;
            ig_md.l4_dst_port = p.tcp.dport;
        } else if (p.udp.isValid()) {
            ig_md.l4_src_port = p.udp.sport;
            ig_md.l4_dst_port = p.udp.dport;
        } else {
            ig_md.l4_src_port = 16w0;
            ig_md.l4_dst_port = 16w0;
        }

        // Pre-compute quotient and remainder for SRAM bucket indexing
        ig_md.src_quotient = ig_md.l4_src_port[15:5];
        ig_md.src_remainder = ig_md.l4_src_port[4:0];
        ig_md.dst_quotient = ig_md.l4_dst_port[15:5];
        ig_md.dst_remainder = ig_md.l4_dst_port[4:0];

        // =====================================================================
        // Path A: 5-Tuple TCAM (Highest Priority)
        // =====================================================================
        if (five_tuple_tcam.apply().hit) {
            ig_md.five_tuple_hit = true;
            // forward_to_port2 action is executed by table
            // Packet forwarded to port 2/0 (dev_port=144)
            return;
        }

        // =====================================================================
        // Path B: HyperLens Main Pipeline
        // =====================================================================

        // -------------------------------------------------------------------
        // Step 1: IP Table (Stage 1)
        // -------------------------------------------------------------------
        if (!ip_table.apply().hit) {
            ig_md.drop_reason = 8w1;  // MISS_IP_TABLE
            if (THROUGHPUT_TEST_MODE) {
                // In throughput test mode, don't drop; forward to port 2/0
                forward_to_port2();
                return;
            } else {
                // Real mode: drop the packet
                ig_dprsr_md.drop_ctl = 0x1;
                return;
            }
        }

        // -------------------------------------------------------------------
        // Step 2: SRC Port Lookup (Stage 2)
        // -------------------------------------------------------------------

        // Try SRC TCAM path
        src_tcam_table.apply();

        // Try SRC SRAM path (parallel with TCAM)
        src_sram_table.apply();

        // Bitmap membership test for SRAM path using selector table
        if (ig_md.src_sram_bucket_hit) {
            src_bitmap_select_table.apply();  // Sets ig_md.src_bitmap_bit
            if (ig_md.src_bitmap_bit == 1) {
                ig_md.src_sram_bitmap_hit = true;
            }
        }

        // Priority: TCAM > SRAM > MISS
        bool src_match = false;
        if (ig_md.src_tcam_hit) {
            ig_md.Group_id2 = ig_md.src_gid2_from_tcam;
            src_match = true;
        } else if (ig_md.src_sram_bitmap_hit) {
            ig_md.Group_id2 = ig_md.src_gid2_from_sram;
            src_match = true;
        }

        if (!src_match) {
            ig_md.drop_reason = 8w2;  // MISS_SRC_PORT
            if (THROUGHPUT_TEST_MODE) {
                // In throughput test mode, don't drop; forward to port 2/0
                forward_to_port2();
                return;
            } else {
                // Real mode: drop the packet
                ig_dprsr_md.drop_ctl = 0x1;
                return;
            }
        }

        // -------------------------------------------------------------------
        // Step 3: DST Port Lookup (Stage 3)
        // -------------------------------------------------------------------

        // Try DST TCAM path
        dst_tcam_table.apply();

        // Try DST SRAM path (parallel with TCAM)
        dst_sram_table.apply();

        // Bitmap membership test for SRAM path using selector table
        if (ig_md.dst_sram_bucket_hit) {
            dst_bitmap_select_table.apply();  // Sets ig_md.dst_bitmap_bit
            if (ig_md.dst_bitmap_bit == 1) {
                ig_md.dst_sram_bitmap_hit = true;
            }
        }

        // Priority: TCAM > SRAM > MISS
        bool dst_match = false;
        if (ig_md.dst_tcam_hit) {
            // Requirement: any DST hit should forward to port 2/0
            forward_to_port2();
            dst_match = true;
        } else if (ig_md.dst_sram_bitmap_hit) {
            // Requirement: any DST hit should forward to port 2/0
            forward_to_port2();
            dst_match = true;
        }

        if (!dst_match) {
            ig_md.drop_reason = 8w3;  // MISS_DST_PORT
            if (THROUGHPUT_TEST_MODE) {
                // In throughput test mode, don't drop; forward to port 2/0
                forward_to_port2();
                return;
            } else {
                // Real mode: drop the packet
                ig_dprsr_md.drop_ctl = 0x1;
                return;
            }
        }

        // Success: Packet forwarded to resolved egress port
        ig_md.drop_reason = 8w0;  // SUCCESS
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
        transition select(p.ipv4.proto) {
            6: parse_tcp;      // TCP
            17: parse_udp;     // UDP
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(p.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(p.udp);
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
        // Egress 无需特殊处理
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
