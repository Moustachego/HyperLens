###############################################################
 # Name:      Controller
 # Purpose:   Demonstrate basic control plane operations for Tofino2
 # Author:    weijzh (weijzh@pcl.ac.cn)
 # Created:   2025-10-23
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
from src.ACL_handler import IP_PROTO_ACL


this_dir = os.path.dirname(os.path.abspath(__file__))
client_id = 0
p4_name = "tofino2"

logging.basicConfig(
    level=logging.INFO,                               # 
    format='[%(asctime)s] %(levelname)s: %(message)s' # 
)
logger = logging.getLogger(__name__)
#swports = get_sw_ports()
swports = []
for (device, port, ifname) in ptf.config['interfaces']:
    swports.append(port)
swports.sort()
print('    SWPorts:', swports)

# sip = '192.168.85.0'
# mask = '255.255.255.0'
# dip = '20.0.0.0'
# proto = 17 
#(src_ip, src_mask, dst_ip, dst_mask, proto)
entries = [
     ('192.168.85.0', '255.255.255.0', '20.0.0.0', '255.255.255.0', 17, 30, 80),
     ('192.168.60.0', '255.255.255.0', '20.0.2.0', '255.255.255.0', 17, 80, 30)
     ]    # UDP



class P4lensTest(BfRuntimeTest):
    def setUp(self):
        BfRuntimeTest.setUp(self, client_id, p4_name)
    
    def runTest(self):
        key_list = []
        data_list = []
        group_id_list = []
        Group_id_base = 0
        bfrt_info = self.interface.bfrt_info_get(p4_name)
        target = gc_client.Target(device_id=0, pipe_id=0xffff)
        # IP table
        ip_table = bfrt_info.table_get("SwitchIngress.ip_table")                
        ip_table.info.key_field_annotation_add("p.ipv4.src", "ipv4")
        ip_table.info.key_field_annotation_add("p.ipv4.dst", "ipv4")

        # Port table
        port_table = bfrt_info.table_get("SwitchIngress.port_table")

        ################################################
        # Add key,data for IP table
        ################################################
        
        for idx, (sip, smask, dip, dmask, proto, src_port, dst_port) in enumerate(entries): 
            gid = Group_id_base + idx
            group_id_list.append(gid)

            key = ip_table.make_key([
                gc_client.KeyTuple('$MATCH_PRIORITY', 1),
                gc_client.KeyTuple('vrf', 0),
                gc_client.KeyTuple("p.ipv4.src", sip, smask),   # ternary
                gc_client.KeyTuple("p.ipv4.dst", dip, dmask),   # ternary
                gc_client.KeyTuple("p.ipv4.proto", proto),      # exact
            ])
            data = ip_table.make_data([gc_client.DataTuple('Group_id', gid)], 'get_coupling_info')##

            key_list.append(key)
            data_list.append(data)
        
        ip_table.entry_add(target, key_list, data_list)
        logger.info(">>> %d entries inserted into ip_table", len(key_list))

        #check get from hw using group_id
        resp = ip_table.entry_get(target, None, {"from_hw": False})
        logger.info(">>> Verifying inserted entries ...")
        seen_gids = []        
        for data, key in resp:
            d = data.to_dict()
            if 'Group_id' in d:
                seen_gids.append(d['Group_id'])
        logger.info("ip_table group ids seen: %s", seen_gids)
        # 
        assert len(seen_gids) >= len(group_id_list)

        ################################################
        # Add key/data for Port table
        ################################################
        port_key_list = []
        port_data_list = []


        for i, gid in enumerate(group_id_list):
            sip, smask, dip, dmask, proto, src_port, dst_port = entries[i]
            
            key = port_table.make_key([
                gc_client.KeyTuple('ig_md.Group_id', gid),
                gc_client.KeyTuple('p.udp.sport', src_port),
                gc_client.KeyTuple('p.udp.dport', dst_port)
            ])

            if gid % 2 == 0:
                action_name = 'forward'
                data = port_table.make_data([gc_client.DataTuple('port', swports[10])], action_name)
            else:
                action_name = 'drop'
                data = port_table.make_data([], action_name)

            port_key_list.append(key)
            port_data_list.append(data)

        port_table.entry_add(target, port_key_list, port_data_list)
        logger.info(">>> %d entries inserted into port_table", len(port_key_list))


        ################################################
        # Send test packets and verify
        ################################################
        for i, gid in enumerate(group_id_list):
            sip, smask, dip, dmask, proto, sport, dport = entries[i]
            # 构建包
            if proto == 17:
                pkt = testutils.simple_udp_packet(ip_src=sip, ip_dst=dip, udp_sport=sport, udp_dport=dport)
            else:
                pkt = testutils.simple_tcp_packet(ip_src=sip, ip_dst=dip, tcp_sport=sport, tcp_dport=dport)

            testutils.send_packet(self, swports[1], pkt)

            # 根据 port_table 决定动作
            if gid % 2 == 0:
                # forward
                exp_port = swports[2]
                testutils.verify_packet(self, pkt, exp_port)
            else:
                # drop
                testutils.verify_no_other_packets(self)


        ################################################
        # Delete all entries  
        ################################################

        logger.info(">>> [DELETE] start deleting all entries in ip_table & port_table")

        # 1) 先检查 entry 数量
        def count_entries(tbl, name):
            resp = list(tbl.entry_get(target, None))
            logger.info("[CHECK] %s 当前 entry 数量 = %d", name, len(resp))
            return len(resp)

        count_entries(ip_table,   "ip_table")
        count_entries(port_table, "port_table")

        # 2)
        ip_table.entry_del(target, None)
        port_table.entry_del(target, None)
        logger.info(">>> [DELETE] ip_table & port_table 已执行 entry_del(..., None)")

        # 3)
        count_entries(ip_table,   "ip_table")
        count_entries(port_table, "port_table")
        logger.info(">>> [DELETE] done.")