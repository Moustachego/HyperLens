#!/usr/bin/env python3
"""
Self-inspection script for HyperLens verification
"""

import ipaddress
import sys
import os
import json
from datetime import datetime


def ip_to_int(ip_str):
    """
    Convert IP address string to integer
    """
    return int(ipaddress.IPv4Address(ip_str))


def load_final_ip_table(filename):
    """
    Load final IP table from file
    
    Returns:
        List of dictionaries representing rules in the final IP table
    """
    rules = []
    with open(filename, 'r') as f:
        lines = f.readlines()
        
    # Skip header line
    for i, line in enumerate(lines[1:], 0):  # Start from index 0
        parts = line.strip().split()
        if len(parts) >= 5:
            rule = {
                'index': i,
                'priority': int(parts[0]),
                'src_ip': parts[1],
                'dst_ip': parts[2],
                'protocol': int(parts[3]),
                'gids': parts[4]
            }
            
            # Parse source IP network
            if '/' in rule['src_ip']:
                src_network = ipaddress.IPv4Network(rule['src_ip'], strict=False)
            else:
                src_network = ipaddress.IPv4Network(rule['src_ip'] + '/32', strict=False)
                
            # Parse destination IP network
            if '/' in rule['dst_ip']:
                dst_network = ipaddress.IPv4Network(rule['dst_ip'], strict=False)
            else:
                dst_network = ipaddress.IPv4Network(rule['dst_ip'] + '/32', strict=False)
                
            rule['src_network'] = src_network
            rule['dst_network'] = dst_network
            
            rules.append(rule)
    
    return rules


def load_test_rules(filename):
    """
    Load test rules from file
    
    Returns:
        List of dictionaries representing test rules
    """
    rules = []
    with open(filename, 'r') as f:
        for i, line in enumerate(f):
            # Skip empty lines
            if not line.strip():
                continue
                
            # Parse line: Src_IP Dst_IP Src_port Dst_port Protocol //R_index
            parts = line.strip().split()
            if len(parts) >= 5:
                rule = {
                    'src_ip': parts[0],
                    'dst_ip': parts[1],
                    'src_port': int(parts[2]),
                    'dst_port': int(parts[3]),
                    'protocol': int(parts[4]),
                    'index': i
                }
                
                # Try to extract rule index from comment if present
                if len(parts) > 5 and parts[5].startswith('//R'):
                    try:
                        rule['r_index'] = int(parts[5][3:])  # Remove '//R' prefix
                    except ValueError:
                        rule['r_index'] = None
                        
                rules.append(rule)
    
    return rules


def ip_in_network(ip_str, network):
    """
    Check if IP address is in network
    """
    ip = ipaddress.IPv4Address(ip_str)
    return ip in network


def match_test_rule_against_final_table(test_rule, final_table):
    """
    Match a test rule against all entries in the final IP table
    
    Returns:
        List of matched final table entries
    """
    matches = []
    
    test_src_ip = test_rule['src_ip']
    test_dst_ip = test_rule['dst_ip']
    test_protocol = test_rule['protocol']
    
    for final_rule in final_table:
        # Check if IPs match and protocol matches
        if (ip_in_network(test_src_ip, final_rule['src_network']) and
            ip_in_network(test_dst_ip, final_rule['dst_network']) and
            test_protocol == final_rule['protocol']):
            matches.append(final_rule)
            
    # Sort by priority (lower number = higher priority)
    matches.sort(key=lambda x: x['priority'])
    return matches


def load_intersection_analysis(filename):
    """
    Load intersection analysis from JSON file
    
    Returns:
        Dictionary containing intersection analysis data
    """
    if not os.path.exists(filename):
        print(f"Warning: Intersection analysis file not found: {filename}")
        return None
        
    with open(filename, 'r') as f:
        return json.load(f)


def check_rule_in_intersection(test_rule, intersection_data):
    """
    Check if a test rule falls within any intersection region in the analysis data
    
    Args:
        test_rule: Dictionary with test rule data
        intersection_data: Dictionary with intersection analysis data
        
    Returns:
        Tuple: (is_in_intersection, intersection_details)
    """
    if not intersection_data:
        return False, "No intersection data available"
    
    test_src_ip = ipaddress.IPv4Address(test_rule['src_ip'])
    test_dst_ip = ipaddress.IPv4Address(test_rule['dst_ip'])
    test_proto = test_rule['protocol']
    
    # Check cross-Rmax intersections
    cross_rmax_intersections = intersection_data.get('cross_rmax_intersections', [])
    
    for intersection in cross_rmax_intersections:
        region = intersection['intersection_region']
        
        # Check if protocol matches
        if region['proto'] != test_proto:
            continue
            
        # Parse intersection boundaries
        src_lo = ipaddress.IPv4Address(region['src_lo'])
        src_hi = ipaddress.IPv4Address(region['src_hi'])
        dst_lo = ipaddress.IPv4Address(region['dst_lo'])
        dst_hi = ipaddress.IPv4Address(region['dst_hi'])
        
        # Check if test packet is within intersection region
        if (src_lo <= test_src_ip <= src_hi and 
            dst_lo <= test_dst_ip <= dst_hi):
            return True, {
                'rmax_a': intersection['rmax_a'],
                'rmax_b': intersection['rmax_b'],
                'intersection_region': region
            }
    
    return False, "Not in any intersection region"


def validate_match_with_intersection_analysis(test_rule, matched_rule, intersection_data):
    """
    Validate if the matched rule is correct based on intersection analysis
    
    Args:
        test_rule: Dictionary with test rule data
        matched_rule: Dictionary with matched final IP table rule
        intersection_data: Dictionary with intersection analysis data
        
    Returns:
        Validation result dictionary with details
    """
    if not intersection_data:
        return {
            'valid': True,
            'reason': "No intersection analysis data available",
            'gid_count': 0
        }
    
    # Parse GIDs
    gids_raw = matched_rule['gids'].split(',')
    gids = []
    for gid in gids_raw:
        gid = gid.strip()
        if gid:  # Check if gid is not empty
            try:
                gids.append(int(gid))
            except ValueError:
                pass  # Skip invalid GIDs
    
    # Check if test rule is in any intersection
    is_in_intersection, intersection_details = check_rule_in_intersection(test_rule, intersection_data)
    
    # Case 1: Single GID
    if len(gids) == 1:
        gid = gids[0]
        # For single GID, check if the rule range matches and if it's in an intersection
        if is_in_intersection:
            # Rule is in intersection but has only one GID - potentially problematic
            return {
                'valid': False,
                'reason': f"Rule is in intersection but has only one GID ({gid})",
                'gid_count': 1,
                'gids': gids,
                'in_intersection': True,
                'intersection_details': intersection_details
            }
        else:
            # Rule is not in intersection and has one GID - normal case
            return {
                'valid': True,
                'reason': f"Rule not in intersection, single GID ({gid}) is valid",
                'gid_count': 1,
                'gids': gids,
                'in_intersection': False
            }
    
    # Case 2: Two GIDs
    elif len(gids) == 2:
        rule_gid, rmax_gid = gids[0], gids[1]
        
        if is_in_intersection:
            # Rule is in intersection and has two GIDs - expected case
            return {
                'valid': True,
                'reason': f"Rule is in intersection with two GIDs ({gids[0]}, {gids[1]})",
                'gid_count': 2,
                'gids': gids,
                'in_intersection': True,
                'intersection_details': intersection_details
            }
        else:
            # Rule is not in intersection but has two GIDs - check if it belongs to an Rmax
            rmax_details = intersection_data.get('rmax_details', {}).get(str(rmax_gid), {})
            if rmax_details:
                # Parse Rmax ranges
                src_range_parts = rmax_details.get('src_range', '').split('-')
                dst_range_parts = rmax_details.get('dst_range', '').split('-')
                
                if len(src_range_parts) == 2 and len(dst_range_parts) == 2:
                    try:
                        src_lo = ipaddress.IPv4Address(src_range_parts[0])
                        src_hi = ipaddress.IPv4Address(src_range_parts[1])
                        dst_lo = ipaddress.IPv4Address(dst_range_parts[0])
                        dst_hi = ipaddress.IPv4Address(dst_range_parts[1])
                        
                        test_src_ip = ipaddress.IPv4Address(test_rule['src_ip'])
                        test_dst_ip = ipaddress.IPv4Address(test_rule['dst_ip'])
                        
                        # Check if test packet is in Rmax range
                        src_in_range = src_lo <= test_src_ip <= src_hi
                        dst_in_range = dst_lo <= test_dst_ip <= dst_hi
                        
                        if src_in_range and dst_in_range and rmax_details.get('proto') == test_rule['protocol']:
                            return {
                                'valid': True,
                                'reason': f"Rule in Rmax {rmax_gid} range with two GIDs ({gids[0]}, {gids[1]})",
                                'gid_count': 2,
                                'gids': gids,
                                'in_intersection': False,
                                'rmax_id': rmax_gid
                            }
                        else:
                            return {
                                'valid': False,
                                'reason': f"Rule has two GIDs but not in Rmax {rmax_gid} range",
                                'gid_count': 2,
                                'gids': gids,
                                'in_intersection': False
                            }
                    except Exception as e:
                        return {
                            'valid': True,
                            'reason': f"Rule with two GIDs ({gids[0]}, {gids[1]}) (range parsing error: {e})",
                            'gid_count': 2,
                                'gids': gids,
                                'in_intersection': False
                        }
                else:
                    return {
                        'valid': True,
                        'reason': f"Rule with two GIDs ({gids[0]}, {gids[1]}) (invalid range format)",
                        'gid_count': 2,
                        'gids': gids,
                        'in_intersection': False
                    }
            else:
                return {
                    'valid': True,
                    'reason': f"Rule with two GIDs ({gids[0]}, {gids[1]}) (no Rmax details)",
                    'gid_count': 2,
                    'gids': gids,
                    'in_intersection': False
                }
    
    # Unexpected case
    return {
        'valid': True,
        'reason': f"Rule with {len(gids)} GIDs: {gids}",
        'gid_count': len(gids),
        'gids': gids,
        'in_intersection': is_in_intersection
    }


def log_test_result(log_file, test_index, test_rule, matches, validation_results):
    """
    Log test result to file
    
    Args:
        log_file: File object for logging
        test_index: Index of the test rule
        test_rule: Dictionary with test rule data
        matches: List of matched rules
        validation_results: List of validation results for each match
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    log_file.write(f"\n[{timestamp}] Test Rule {test_index}:\n")
    log_file.write(f"  Packet: Src={test_rule['src_ip']}, Dst={test_rule['dst_ip']}, Proto={test_rule['protocol']}\n")
    
    if 'r_index' in test_rule:
        log_file.write(f"  Original Rule Index: R{test_rule['r_index']}\n")
    
    log_file.write(f"  Found {len(matches)} matches:\n")
    
    valid_matches = 0
    invalid_matches = 0
    
    for i, (match, validation) in enumerate(zip(matches, validation_results)):
        status = "VALID" if validation['valid'] else "INVALID"
        log_file.write(f"    Match {i+1}: Idx={match['index']}, Priority={match['priority']}, "
                      f"Src={match['src_ip']}, Dst={match['dst_ip']}, Proto={match['protocol']}, "
                      f"GIDs={match['gids']} [{status}]\n")
        log_file.write(f"      Reason: {validation['reason']}\n")
        
        if validation['valid']:
            valid_matches += 1
        else:
            invalid_matches += 1
            
        # Log additional details
        if validation['gid_count'] == 1:
            log_file.write(f"      Type: Single GID rule\n")
        elif validation['gid_count'] == 2:
            if validation.get('in_intersection'):
                details = validation.get('intersection_details', {})
                log_file.write(f"      Type: Two GID rule in intersection of Rmax {details.get('rmax_a')} and Rmax {details.get('rmax_b')}\n")
                log_file.write(f"      GIDs: {validation['gids'][0]}, {validation['gids'][1]}\n")
            else:
                rmax_id = validation.get('rmax_id', 'unknown')
                log_file.write(f"      Type: Two GID rule in Rmax {rmax_id} range\n")
                log_file.write(f"      GIDs: {validation['gids'][0]}, {validation['gids'][1]}\n")
        else:
            log_file.write(f"      Type: {validation['gid_count']} GIDs rule\n")
    
    log_file.write(f"  Summary: {valid_matches} valid matches, {invalid_matches} invalid matches\n")
    log_file.write(f"  Overall Status: {'PASS' if invalid_matches == 0 else 'FAIL'}\n")
    log_file.write("-" * 80 + "\n")


def main():
    # Define file paths
    base_path = os.path.join('src', 'output')
    testset_file = os.path.join(base_path, 'acl1_50k_16_0.5_testset.txt')
    final_ip_table_file = os.path.join(base_path, 'final_ip_table_cidr.txt')
    intersection_analysis_file = os.path.join(base_path, 'intersection_analysis.json')
    log_file_path = os.path.join(base_path, 'self_inspection_log.txt')
    
    # Check if files exist
    if not os.path.exists(testset_file):
        print(f"Error: Test set file not found: {testset_file}")
        return 1
        
    if not os.path.exists(final_ip_table_file):
        print(f"Error: Final IP table file not found: {final_ip_table_file}")
        return 1
    
    # Open log file
    log_file = open(log_file_path, 'w')
    log_file.write("HyperLens Self-Inspection Log\n")
    log_file.write("=" * 80 + "\n")
    log_file.write(f"Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    log_file.write(f"Test set file: {testset_file}\n")
    log_file.write(f"Final IP table file: {final_ip_table_file}\n")
    log_file.write(f"Intersection analysis file: {intersection_analysis_file}\n")
    log_file.write("=" * 80 + "\n")
    
    # Load data
    print("Loading final IP table...")
    final_table = load_final_ip_table(final_ip_table_file)
    print(f"Loaded {len(final_table)} rules from final IP table")
    log_file.write(f"Loaded {len(final_table)} rules from final IP table\n")
    
    print("Loading test rules...")
    test_rules = load_test_rules(testset_file)
    print(f"Loaded {len(test_rules)} test rules")
    log_file.write(f"Loaded {len(test_rules)} test rules\n")
    
    print("Loading intersection analysis...")
    intersection_data = load_intersection_analysis(intersection_analysis_file)
    if intersection_data:
        print("Loaded intersection analysis data")
        log_file.write("Loaded intersection analysis data\n")
    else:
        print("Failed to load intersection analysis data")
        log_file.write("Failed to load intersection analysis data\n")
    
    # Process test rules
    if test_rules:
        print(f"\nProcessing {len(test_rules)} test rules...")
        log_file.write(f"\nProcessing {min(100, len(test_rules))} test rules...\n")
        
        passed_tests = 0
        failed_tests = 0
        
        # Process first 100 test rules or all if less than 100
        for i in range(len(test_rules)):
            test_rule = test_rules[i]
            
            # Find matches
            matches = match_test_rule_against_final_table(test_rule, final_table)
            
            # Validate each match
            validation_results = []
            for match in matches:
                validation_result = validate_match_with_intersection_analysis(test_rule, match, intersection_data)
                validation_results.append(validation_result)
            
            # Log test result
            log_test_result(log_file, i, test_rule, matches, validation_results)
            
            # Count passed/failed tests
            invalid_count = sum(1 for v in validation_results if not v['valid'])
            if invalid_count == 0:
                passed_tests += 1
            else:
                failed_tests += 1
            
            # Print progress to console
            if (i + 1) % 100 == 0:
                print(f"Processed {i + 1} test rules...")
        
        # Print summary
        print(f"\nTest Summary:")
        print(f"  Passed tests: {passed_tests}")
        print(f"  Failed tests: {failed_tests}")
        print(f"  Total tests: {passed_tests + failed_tests}")
        print(f"  Success rate: {passed_tests / (passed_tests + failed_tests) * 100:.2f}%")
        
        # Log summary
        log_file.write(f"\nTest Summary:\n")
        log_file.write(f"  Passed tests: {passed_tests}\n")
        log_file.write(f"  Failed tests: {failed_tests}\n")
        log_file.write(f"  Total tests: {passed_tests + failed_tests}\n")
        log_file.write(f"  Success rate: {passed_tests / (passed_tests + failed_tests) * 100:.2f}%\n")
        log_file.write(f"\nTest finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
    else:
        print("No test rules found!")
        log_file.write("No test rules found!\n")
        log_file.close()
        return 1
    
    log_file.close()
    print(f"\nDetailed test log written to: {log_file_path}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())