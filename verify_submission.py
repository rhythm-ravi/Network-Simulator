#!/usr/bin/env python3
"""
Submission Verification Script

This script verifies that all required deliverables are present and functional
for the Cisco Virtual Internship Program 2025 submission.
"""

import os
import json
from pathlib import Path

def verify_deliverables():
    """Verify all submission deliverables are present."""
    
    print("=" * 80)
    print("CISCO VIRTUAL INTERNSHIP PROGRAM 2025 - SUBMISSION VERIFICATION")
    print("=" * 80)
    
    base_path = Path(".")
    verification_results = {}
    
    # 1. Verify main report
    print("\n1. COMPREHENSIVE ANALYSIS REPORT")
    print("-" * 40)
    
    report_file = base_path / "report.md"
    if report_file.exists():
        file_size = report_file.stat().st_size
        print(f"✓ report.md found ({file_size:,} bytes)")
        verification_results['report'] = {'status': 'found', 'size': file_size}
        
        # Check report content
        with open(report_file, 'r') as f:
            content = f.read()
            word_count = len(content.split())
            print(f"✓ Report contains {word_count:,} words")
            verification_results['report']['word_count'] = word_count
    else:
        print("✗ report.md NOT FOUND")
        verification_results['report'] = {'status': 'missing'}
    
    # 2. Verify Packet Tracer files
    print("\n2. PACKET TRACER FILES")
    print("-" * 40)
    
    pkt_dir = base_path / "outputs" / "packet_tracer_files"
    expected_pkt_files = [
        "campus_network.pkt",
        "enterprise_network.pkt", 
        "datacenter_network.pkt",
        "simple_test_network.pkt"
    ]
    
    verification_results['packet_tracer'] = {'files': {}, 'total_found': 0}
    
    if pkt_dir.exists():
        for pkt_file in expected_pkt_files:
            file_path = pkt_dir / pkt_file
            if file_path.exists():
                file_size = file_path.stat().st_size
                print(f"✓ {pkt_file} found ({file_size} bytes)")
                verification_results['packet_tracer']['files'][pkt_file] = {'status': 'found', 'size': file_size}
                verification_results['packet_tracer']['total_found'] += 1
            else:
                print(f"✗ {pkt_file} NOT FOUND")
                verification_results['packet_tracer']['files'][pkt_file] = {'status': 'missing'}
    else:
        print("✗ Packet Tracer directory NOT FOUND")
        for pkt_file in expected_pkt_files:
            verification_results['packet_tracer']['files'][pkt_file] = {'status': 'missing'}
    
    # 3. Verify test results and visualizations
    print("\n3. NETWORK ANALYSIS RESULTS")
    print("-" * 40)
    
    test_results_dir = base_path / "outputs" / "test_results"
    expected_scenarios = ["campus", "enterprise", "datacenter", "simple"]
    
    verification_results['test_results'] = {'scenarios': {}, 'total_found': 0}
    
    if test_results_dir.exists():
        for scenario in expected_scenarios:
            scenario_dir = test_results_dir / scenario
            if scenario_dir.exists():
                # Check for required files
                required_files = [
                    "test_report.txt",
                    "test_results.json", 
                    "test_report.html",
                    "network_topology.png"
                ]
                
                scenario_files = {}
                all_found = True
                
                for req_file in required_files:
                    file_path = scenario_dir / req_file
                    if file_path.exists():
                        file_size = file_path.stat().st_size
                        scenario_files[req_file] = {'status': 'found', 'size': file_size}
                    else:
                        scenario_files[req_file] = {'status': 'missing'}
                        all_found = False
                
                if all_found:
                    print(f"✓ {scenario} scenario complete (all files present)")
                    verification_results['test_results']['total_found'] += 1
                else:
                    print(f"⚠ {scenario} scenario incomplete (some files missing)")
                
                verification_results['test_results']['scenarios'][scenario] = scenario_files
            else:
                print(f"✗ {scenario} scenario NOT FOUND")
                verification_results['test_results']['scenarios'][scenario] = {'status': 'missing'}
    else:
        print("✗ Test results directory NOT FOUND")
    
    # 4. Verify core framework
    print("\n4. CORE FRAMEWORK FILES")
    print("-" * 40)
    
    framework_files = [
        "test_network_simulator.py",
        "generate_packet_tracer_files.py",
        "network_analyzer.py",
        "requirements.txt"
    ]
    
    verification_results['framework'] = {'files': {}, 'total_found': 0}
    
    for framework_file in framework_files:
        file_path = base_path / framework_file
        if file_path.exists():
            file_size = file_path.stat().st_size
            print(f"✓ {framework_file} found ({file_size} bytes)")
            verification_results['framework']['files'][framework_file] = {'status': 'found', 'size': file_size}
            verification_results['framework']['total_found'] += 1
        else:
            print(f"✗ {framework_file} NOT FOUND")
            verification_results['framework']['files'][framework_file] = {'status': 'missing'}
    
    # 5. Verify configuration files
    print("\n5. NETWORK CONFIGURATION FILES")
    print("-" * 40)
    
    config_dir = base_path / "configs" / "scenarios"
    verification_results['configurations'] = {'scenarios': {}, 'total_devices': 0}
    
    if config_dir.exists():
        for scenario in expected_scenarios:
            scenario_dir = config_dir / scenario
            if scenario_dir.exists():
                config_files = list(scenario_dir.glob("*.config.dump"))
                device_count = len(config_files)
                print(f"✓ {scenario} configurations found ({device_count} devices)")
                verification_results['configurations']['scenarios'][scenario] = {
                    'status': 'found', 
                    'device_count': device_count,
                    'devices': [f.stem for f in config_files]
                }
                verification_results['configurations']['total_devices'] += device_count
            else:
                print(f"✗ {scenario} configurations NOT FOUND")
                verification_results['configurations']['scenarios'][scenario] = {'status': 'missing'}
    else:
        print("✗ Configuration directory NOT FOUND")
    
    # Summary
    print("\n" + "=" * 80)
    print("VERIFICATION SUMMARY")
    print("=" * 80)
    
    total_score = 0
    max_score = 0
    
    # Report score
    if verification_results['report']['status'] == 'found':
        print(f"✓ Comprehensive Report: PRESENT ({verification_results['report']['word_count']:,} words)")
        total_score += 1
    else:
        print("✗ Comprehensive Report: MISSING")
    max_score += 1
    
    # PKT files score
    pkt_found = verification_results['packet_tracer']['total_found']
    pkt_expected = len(expected_pkt_files)
    print(f"{'✓' if pkt_found == pkt_expected else '⚠'} Packet Tracer Files: {pkt_found}/{pkt_expected}")
    if pkt_found == pkt_expected:
        total_score += 1
    max_score += 1
    
    # Test results score
    results_found = verification_results['test_results']['total_found']
    results_expected = len(expected_scenarios)
    print(f"{'✓' if results_found == results_expected else '⚠'} Network Analysis: {results_found}/{results_expected} scenarios")
    if results_found == results_expected:
        total_score += 1
    max_score += 1
    
    # Framework score
    framework_found = verification_results['framework']['total_found']
    framework_expected = len(framework_files)
    print(f"{'✓' if framework_found == framework_expected else '⚠'} Framework Files: {framework_found}/{framework_expected}")
    if framework_found == framework_expected:
        total_score += 1
    max_score += 1
    
    # Configuration score
    total_devices = verification_results['configurations']['total_devices']
    print(f"✓ Network Configurations: {total_devices} devices across {len(expected_scenarios)} scenarios")
    if total_devices > 0:
        total_score += 1
    max_score += 1
    
    # Final score
    percentage = (total_score / max_score) * 100
    print("\n" + "-" * 80)
    print(f"OVERALL SUBMISSION STATUS: {total_score}/{max_score} ({percentage:.1f}%)")
    
    if percentage == 100:
        print("🎉 SUBMISSION COMPLETE - All deliverables present!")
    elif percentage >= 80:
        print("⚠️  SUBMISSION MOSTLY COMPLETE - Some items may be missing")
    else:
        print("❌ SUBMISSION INCOMPLETE - Missing critical deliverables")
    
    print("=" * 80)
    
    # Save verification results
    verification_file = base_path / "verification_results.json"
    with open(verification_file, 'w') as f:
        json.dump(verification_results, f, indent=2)
    
    print(f"Verification results saved to: {verification_file}")
    
    return percentage == 100


if __name__ == "__main__":
    success = verify_deliverables()
    exit(0 if success else 1)