#!/bin/bash
#
# Test all network scenarios to validate comprehensive testing capability
# This script demonstrates the enhanced testing against complex configurations
#
echo "================================================================================"
echo "NETWORK SIMULATOR - COMPREHENSIVE SCENARIO TESTING"
echo "================================================================================"
echo "Testing all network scenarios to validate complex configurations..."
echo

# Function to run test and report results
run_scenario_test() {
    local scenario=$1
    local description=$2
    
    echo "📋 Testing $description..."
    echo "   Config: configs/scenarios/$scenario"
    echo "   Output: outputs/test_results/$scenario"
    
    # Create output directory for this scenario
    mkdir -p "outputs/test_results/$scenario"
    
    # Run the test
    python test_network_simulator.py \
        --config-dir "configs/scenarios/$scenario" \
        --output-dir "outputs/test_results/$scenario" \
        --html \
        --verbose > "outputs/test_results/$scenario/test_log.txt" 2>&1
    
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        echo "   ✅ PASSED - Test completed successfully"
    else
        echo "   ❌ FAILED - Test failed (exit code: $exit_code)"
    fi
    
    # Get device count from log
    local devices=$(grep "parsed successfully" "outputs/test_results/$scenario/test_log.txt" | tail -1 | awk '{print $3}')
    if [ ! -z "$devices" ]; then
        echo "   📊 Devices parsed: $devices"
    fi
    
    # Get issues found
    local issues=$(grep "Found .* network issues" "outputs/test_results/$scenario/test_log.txt" | tail -1 | awk '{print $3}')
    if [ ! -z "$issues" ]; then
        echo "   ⚠️  Issues detected: $issues"
    fi
    
    echo
}

# Test all scenarios
echo "🚀 Starting comprehensive scenario testing..."
echo

run_scenario_test "simple" "Simple Network Scenarios (3-4 devices)"
run_scenario_test "enterprise" "Enterprise Network Scenario (7 devices)" 
run_scenario_test "campus" "Campus Network Scenario (4-6 devices)"
run_scenario_test "datacenter" "Data Center Network Scenario (3-6 devices)"

echo "================================================================================"
echo "TESTING COMPLETE"
echo "================================================================================"
echo "📁 All test results saved in: outputs/test_results/"
echo "🔍 Individual scenario results:"
echo "   • Simple: outputs/test_results/simple/"
echo "   • Enterprise: outputs/test_results/enterprise/"  
echo "   • Campus: outputs/test_results/campus/"
echo "   • Data Center: outputs/test_results/datacenter/"
echo
echo "💡 Each scenario directory contains:"
echo "   • test_report.html - Interactive HTML report"
echo "   • test_results.json - Structured JSON data"
echo "   • test_report.txt - CLI summary report"
echo "   • network_topology.png - Network visualization"
echo "   • test_log.txt - Detailed execution log"
echo
echo "✨ Complex network testing validation complete!"
echo "================================================================================"