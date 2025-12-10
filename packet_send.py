from scapy.all import *
import time

# Define the file path
file_path = "/home/long/Desktop/HyperLens/src/output/acl1_50k_16_0.5_testset.txt"

# Function to read packet details from the file and send packets
def send_packets_from_file(file_path, num_packets=None, iface="veth0", delay=1, start=0, end=None):
    """
    Send packets from a test dataset file.
    
    Args:
        file_path: Path to the test dataset file
        num_packets: Max number of packets to send (deprecated, use end instead)
        iface: Network interface to send packets on
        delay: Delay between packets in seconds
        start: Starting line index (0-based, inclusive)
        end: Ending line index (exclusive). If None, send until EOF or num_packets reached
    """
    # Open the file and read lines
    with open(file_path, "r") as file:
        # Iterate over the lines in the file
        sent_count = 0
        line_index = 0
        
        for line in file:
            # Skip lines before start
            if line_index < start:
                line_index += 1
                continue
            
            # Stop if we've reached the end index
            if end is not None and line_index >= end:
                break
            
            # Stop if we've sent enough packets (for backward compatibility)
            if num_packets is not None and sent_count >= num_packets:
                break

            # Split the line into components (ignore comment field like //R0)
            parts = line.split()
            if len(parts) < 5:
                line_index += 1
                continue
            src_ip, dst_ip, src_port, dst_port, proto = parts[:5]
            
            # Extract rule info from comment if present (e.g., //R0)
            rule_info = parts[5] if len(parts) > 5 else ""

            # Convert the protocol into integer
            proto = int(proto)

            # Construct the packet based on protocol
            if proto == 6:  # TCP
                packet = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=int(src_port), dport=int(dst_port))
            elif proto == 17:  # UDP
                packet = Ether()/IP(src=src_ip, dst=dst_ip)/UDP(sport=int(src_port), dport=int(dst_port))
            elif proto == 1:  # ICMP
                packet = Ether()/IP(src=src_ip, dst=dst_ip)/ICMP()
            elif proto == 58:  # ICMPv6 (just in case)
                packet = Ether()/IPv6(src=src_ip, dst=dst_ip)/ICMPv6EchoRequest()
            elif proto == 0:  # Reserved or unused, skip
                print(f"[{line_index}] Skipping packet with protocol {proto} (reserved/unused).")
                line_index += 1
                continue
            else:
                print(f"[{line_index}] Unsupported protocol {proto}. Skipping packet.")
                line_index += 1
                continue

            # Send the packet
            sendp(packet, iface=iface)
            print(f"[{line_index}] Sent {packet.summary()} {rule_info}")
            sent_count += 1
            line_index += 1

            # Sleep between packets if necessary
            time.sleep(delay)
    
    print(f"\nTotal packets sent: {sent_count} (from line {start} to {line_index-1})")

# Call the function to send packets
# Examples:
#   send_packets_from_file(file_path, start=0, end=10)      # Send lines 0-9
#   send_packets_from_file(file_path, start=50, end=60)     # Send lines 50-59
#   send_packets_from_file(file_path, start=100)            # Send from line 100 to EOF

import argparse


def send_single_packet(src_ip, dst_ip, src_port, dst_port, proto, iface="veth0"):
    """Send a single packet with the specified 5-tuple."""
    proto = int(proto)
    if proto == 6:  # TCP
        packet = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=int(src_port), dport=int(dst_port))
    elif proto == 17:  # UDP
        packet = Ether()/IP(src=src_ip, dst=dst_ip)/UDP(sport=int(src_port), dport=int(dst_port))
    elif proto == 1:  # ICMP
        packet = Ether()/IP(src=src_ip, dst=dst_ip)/ICMP()
    elif proto == 58:  # ICMPv6 (just in case)
        packet = Ether()/IPv6(src=src_ip, dst=dst_ip)/ICMPv6EchoRequest()
    else:
        print(f"Unsupported protocol {proto}. Skipping packet.")
        return

    sendp(packet, iface=iface)
    print(f"[single] Sent {packet.summary()}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Send test packets from file or single packet')
    parser.add_argument('--single', action='store_true', help='Send a single test packet')
    parser.add_argument('--iface', default='veth0', help='Interface to send packets on')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between packets when sending from file')
    parser.add_argument('--start', type=int, default=5198, help='Start line (inclusive) for file mode')
    parser.add_argument('--end', type=int, default=5201, help='End line (exclusive) for file mode')
    args = parser.parse_args()

    if args.single:
        # Test packet aimed to hit the more specific 34.228.24.0/24 entry under 171.102.8.0/23
        send_single_packet('171.102.9.230', '34.228.24.1', 52072, 1717, 6, iface=args.iface)
    else:
        send_packets_from_file(file_path, iface=args.iface, delay=args.delay, start=args.start, end=args.end)

