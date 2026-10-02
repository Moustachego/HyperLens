###############################################################
 # Name:      Controller
 # Purpose:   Demonstrate basic control plane operations for Tofino2
 # Author:    weijzh (weijzh@pcl.ac.cn)
 # Created:   2025-10-23
 # Modified:  2025-11-25 - Added P4Lens table loading
 # Copyright: weijzh (https://www.pcl.ac.cn)
###############################################################

import logging
import random
import ptf
from ptf import config
import ptf.testutils as testutils
from ptf.testutils import *
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc_client
import socket
import os
from binascii import hexlify
import ipaddress



project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
this_dir = os.path.join(project_root, "src", "output")
client_id = 0
p4_name = "tofino2"

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

swports = []
for (device, port, ifname) in ptf.config['interfaces']:
    swports.append(port)
swports.sort()
print('    SWPorts:', swports)


##############################################################################
# --------------- Helper Functions for Reading Table Files ------------------
##############################################################################

def read_final_ip_table(filename):
    """Read final_ip_table_cidr.txt and parse entries."""
    entries = []
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 5:
                try:
                    priority = int(parts[0])
                except ValueError:
                    continue
                src_cidr = parts[1]
                dst_cidr = parts[2]
                protocol = int(parts[3])
                # GIDs might be comma-separated like "0, 25"
                gids_str = ' '.join(parts[4:])
                gids = [int(x.strip()) for x in gids_str.split(',')]

                entries.append({
                    'priority': priority,
                    'src_cidr': src_cidr,
                    'dst_cidr': dst_cidr,
                    'protocol': protocol,
                    'gids': gids
                })
    logger.info("Loaded %d entries from %s", len(entries), filename)
    return entries


def parse_action_value(action_str):
    """Parse the forwarding-port value from an action/mask string."""
    value_str = action_str.split("/", 1)[0]
    value = int(value_str, 0)
    if not 0 <= value <= 0x1FF:
        raise ValueError("egress port %r does not fit in bit<9>" % action_str)
    return value


def parse_port_ternary(port_str):
    """Parse binary port string with wildcards to (value, mask).
    Example: '00000101110111**' -> (value, mask)
    """
    wildcard_count = port_str.count('*')
    valid_bits = port_str.replace('*', '')

    if not valid_bits:
        # All wildcards
        return 0, 0

    value = int(valid_bits, 2) << wildcard_count
    # Create mask: 1s for valid bits, 0s for wildcards
    mask = ((1 << len(valid_bits)) - 1) << wildcard_count

    return value, mask


def read_src_tcam_table(filename):
    """Read SRC_TCAM_Table.txt and parse entries."""
    entries = []
    with open(filename, 'r') as f:
        # Skip header
        lines = f.readlines()
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 3:
                gid1 = int(parts[0])
                src_port_bin = parts[1]
                gid2 = int(parts[2])

                value, mask = parse_port_ternary(src_port_bin)

                entries.append({
                    'gid1': gid1,
                    'src_port_value': value,
                    'src_port_mask': mask,
                    'gid2': gid2
                })
    logger.info("Loaded %d entries from %s", len(entries), filename)
    return entries


def read_dst_tcam_table(filename):
    """Read DST_TCAM_Table.txt and parse entries."""
    entries = []
    with open(filename, 'r') as f:
        lines = f.readlines()
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 3:
                gid2 = int(parts[0])
                dst_port_bin = parts[1]
                action = parse_action_value(parts[2])

                value, mask = parse_port_ternary(dst_port_bin)

                entries.append({
                    'gid2': gid2,
                    'dst_port_value': value,
                    'dst_port_mask': mask,
                    'action': action
                })
    logger.info("Loaded %d entries from %s", len(entries), filename)
    return entries


def read_src_sram_table(filename):
    """Read SRC_SRAM_Table.txt and parse entries."""
    entries = []
    with open(filename, 'r') as f:
        lines = f.readlines()
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 4:
                gid1 = int(parts[0])
                sp_quotient = int(parts[1])
                bitmap32 = parts[2]
                gid2 = int(parts[3])

                # Convert binary bitmap to integer
                bitmap_value = int(bitmap32, 2)

                entries.append({
                    'gid1': gid1,
                    'sp_quotient': sp_quotient,
                    'bitmap32': bitmap_value,
                    'gid2': gid2
                })
    logger.info("Loaded %d entries from %s", len(entries), filename)
    return entries


def read_dst_sram_table(filename):
    """Read DST_SRAM_Table.txt and parse entries."""
    entries = []
    with open(filename, 'r') as f:
        lines = f.readlines()
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 4:
                gid2 = int(parts[0])
                sp_quotient = int(parts[1])
                bitmap32 = parts[2]
                action = parse_action_value(parts[3])

                bitmap_value = int(bitmap32, 2)

                entries.append({
                    'gid2': gid2,
                    'sp_quotient': sp_quotient,
                    'bitmap32': bitmap_value,
                    'action': action
                })
    logger.info("Loaded %d entries from %s", len(entries), filename)
    return entries


def cidr_to_ip_mask(cidr_str):
    """Convert CIDR notation to IP and mask.
    Example: '10.1.1.0/25' -> ('10.1.1.0', '255.255.255.128')
    """
    network = ipaddress.ip_network(cidr_str, strict=False)
    ip = str(network.network_address)
    mask = str(network.netmask)
    return ip, mask


##############################################################################
# --------------------------- Main Test Class --------------------------------
##############################################################################



class P4lensTest(BfRuntimeTest):
    """Load and install P4Lens tables from generated files."""

    def setUp(self):
        BfRuntimeTest.setUp(self, client_id, p4_name)

    def runTest(self):
        target = gc_client.Target(device_id=0, pipe_id=0xffff)
        bfrt_info = self.interface.bfrt_info_get(p4_name)

        # Get table objects
        ip_table = bfrt_info.table_get("SwitchIngress.ip_table")

        # Add annotations for IP fields
        ip_table.info.key_field_annotation_add("p.ipv4.src", "ipv4")
        ip_table.info.key_field_annotation_add("p.ipv4.dst", "ipv4")

        logger.info("=" * 80)
        logger.info("Starting P4Lens Table Installation")
        logger.info("=" * 80)

        ##################################################################
        # Step 1: Load all table files
        ##################################################################
        logger.info("\n[STEP 1] Loading table files...")

        ip_entries = read_final_ip_table(os.path.join(this_dir, 'final_ip_table_cidr.txt'))
        src_tcam_entries = read_src_tcam_table(os.path.join(this_dir, 'SRC_TCAM_Table.txt'))
        dst_tcam_entries = read_dst_tcam_table(os.path.join(this_dir, 'DST_TCAM_Table.txt'))
        src_sram_entries = read_src_sram_table(os.path.join(this_dir, 'SRC_SRAM_Table.txt'))
        dst_sram_entries = read_dst_sram_table(os.path.join(this_dir, 'DST_SRAM_Table.txt'))

        ##################################################################
        # Step 2: Install IP Table
        ##################################################################
        logger.info("\n[STEP 2] Installing IP Table entries...")

        ip_key_list = []
        ip_data_list = []

        for entry in ip_entries:
            src_ip, src_mask = cidr_to_ip_mask(entry['src_cidr'])
            dst_ip, dst_mask = cidr_to_ip_mask(entry['dst_cidr'])

            # Extract both GIDs from the entry
            gid1 = entry['gids'][0]  # Primary GID
            # For Rmax rules (catch-all), there may be only 1 GID
            # Use 511 (max value for bit<9>) to indicate no secondary GID
            gid_secondary = entry['gids'][1] if len(entry['gids']) > 1 else 511 #511 > G-ID max

            key = ip_table.make_key([
                gc_client.KeyTuple('$MATCH_PRIORITY', entry['priority']),
                gc_client.KeyTuple('vrf', 0),
                gc_client.KeyTuple("p.ipv4.src", src_ip, src_mask),
                gc_client.KeyTuple("p.ipv4.dst", dst_ip, dst_mask),
                gc_client.KeyTuple("p.ipv4.proto", entry['protocol'])
            ])

            data = ip_table.make_data(
                [gc_client.DataTuple('gid1', gid1),
                 gc_client.DataTuple('gid_secondary', gid_secondary)],
                'set_gid1'
            )

            ip_key_list.append(key)
            ip_data_list.append(data)

        # Batch add IP table entries
        ip_table.entry_add(target, ip_key_list, ip_data_list)
        logger.info("✓ Installed %d entries to IP Table", len(ip_key_list))

        ##################################################################
        # Step 3: Install SRC_TCAM Table
        ##################################################################
        logger.info("\n[STEP 3] Installing SRC_TCAM Table entries...")

        def install_src_tcam(table_name, group_field, action_name):
            table = bfrt_info.table_get(table_name)
            keys = []
            data = []
            for idx, entry in enumerate(src_tcam_entries):
                keys.append(table.make_key([
                    gc_client.KeyTuple("$MATCH_PRIORITY", idx + 1),
                    gc_client.KeyTuple(group_field, entry["gid1"]),
                    gc_client.KeyTuple("ig_md.src_port",
                                       entry["src_port_value"],
                                       entry["src_port_mask"])
                ]))
                data.append(table.make_data(
                    [gc_client.DataTuple("gid2", entry["gid2"])],
                    action_name
                ))
            table.entry_add(target, keys, data)
            return len(keys)

        src_tcam_count = install_src_tcam(
            "SwitchIngress.src_tcam_table", "ig_md.Group_id", "set_gid2_from_tcam")
        install_src_tcam(
            "SwitchIngress.src_tcam_table_secondary",
            "ig_md.Group_id_secondary", "set_gid2_from_tcam_secondary")
        logger.info("✓ Installed %d entries to SRC_TCAM tables", src_tcam_count)

        # Step 4: Install DST_TCAM Table
        ##################################################################
        logger.info("\n[STEP 4] Installing DST_TCAM Table entries...")
        dst_tcam_table = bfrt_info.table_get("SwitchIngress.dst_tcam_table")
        dst_tcam_key_list = []
        dst_tcam_data_list = []

        for idx, entry in enumerate(dst_tcam_entries):
            dst_tcam_key_list.append(dst_tcam_table.make_key([
                gc_client.KeyTuple("$MATCH_PRIORITY", idx + 1),
                gc_client.KeyTuple("ig_md.Group_id2", entry["gid2"]),
                gc_client.KeyTuple("ig_md.dst_port",
                                   entry["dst_port_value"],
                                   entry["dst_port_mask"])
            ]))
            dst_tcam_data_list.append(dst_tcam_table.make_data(
                [gc_client.DataTuple("egress_port", entry["action"])],
                "set_action_from_tcam"
            ))

        dst_tcam_table.entry_add(
            target, dst_tcam_key_list, dst_tcam_data_list)
        logger.info("✓ Installed %d entries to DST_TCAM Table",
                    len(dst_tcam_key_list))

        # Step 5: Install SRC_SRAM Table
        ##################################################################
        logger.info("\n[STEP 5] Installing SRC_SRAM Table entries...")

        def install_src_sram(table_name, group_field, action_name):
            table = bfrt_info.table_get(table_name)
            keys = []
            data = []
            for entry in src_sram_entries:
                keys.append(table.make_key([
                    gc_client.KeyTuple(group_field, entry["gid1"]),
                    gc_client.KeyTuple("ig_md.src_quotient",
                                       entry["sp_quotient"])
                ]))
                data.append(table.make_data(
                    [
                        gc_client.DataTuple("bitmap", entry["bitmap32"]),
                        gc_client.DataTuple("gid2", entry["gid2"])
                    ],
                    action_name
                ))
            table.entry_add(target, keys, data)
            return len(keys)

        src_sram_count = install_src_sram(
            "SwitchIngress.src_sram_table", "ig_md.Group_id", "set_src_bitmap")
        install_src_sram(
            "SwitchIngress.src_sram_table_secondary",
            "ig_md.Group_id_secondary", "set_src_bitmap_secondary")
        logger.info("✓ Installed %d entries to SRC_SRAM tables", src_sram_count)

        # Step 6: Install DST_SRAM Table
        ##################################################################
        logger.info("\n[STEP 6] Installing DST_SRAM Table entries...")
        dst_sram_table = bfrt_info.table_get("SwitchIngress.dst_sram_table")
        dst_sram_key_list = []
        dst_sram_data_list = []

        for entry in dst_sram_entries:
            dst_sram_key_list.append(dst_sram_table.make_key([
                gc_client.KeyTuple("ig_md.Group_id2", entry["gid2"]),
                gc_client.KeyTuple("ig_md.dst_quotient",
                                   entry["sp_quotient"])
            ]))
            dst_sram_data_list.append(dst_sram_table.make_data(
                [
                    gc_client.DataTuple("bitmap", entry["bitmap32"]),
                    gc_client.DataTuple("egress_port", entry["action"])
                ],
                "set_dst_bitmap"
            ))

        dst_sram_table.entry_add(
            target, dst_sram_key_list, dst_sram_data_list)
        logger.info("✓ Installed %d entries to DST_SRAM Table",
                    len(dst_sram_key_list))

        # Step 7: Verification
        ##################################################################
        logger.info("\n[STEP 7] Verifying table entries...")

        # Verify IP table
        resp = ip_table.entry_get(target, None, {"from_hw": False})
        ip_count = len(list(resp))
        logger.info("✓ IP Table has %d entries", ip_count)

        logger.info("\n" + "=" * 80)
        logger.info("P4Lens Table Installation Complete!")
        logger.info("=" * 80)
        logger.info("Summary:")
        logger.info("  - IP Table:        %d entries", len(ip_entries))
        logger.info("  - SRC_TCAM:        %d entries", len(src_tcam_entries))
        logger.info("  - DST_TCAM:        %d entries", len(dst_tcam_entries))
        logger.info("  - SRC_SRAM:        %d entries", len(src_sram_entries))
        logger.info("  - DST_SRAM:        %d entries", len(dst_sram_entries))
        logger.info("=" * 80)