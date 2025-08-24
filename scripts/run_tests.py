"""
Run all network simulator tests.
"""
import sys
import os
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).parent
sys.path.append(str(project_root))

# Import test modules
import tests.test_config_parser as test_config_parser
import tests.test_topology_generator as test_topology_generator
import tests.test_network_validator as test_network_validator
import tests.test_integration as test_integration

def run_tests():
    """Run all tests and report results."""
    print("=" * 60)
    print("RUNNING NETWORK SIMULATOR TESTS")
    print("=" * 60)
    
    test_modules = [
        ("Configuration Parser", test_config_parser),
        ("Topology Generator", test_topology_generator),
        ("Network Validator", test_network_validator),
        ("Integration Tests", test_integration)
    ]
    
    all_passed = True
    
    for name, module in test_modules:
        print(f"\n{'-' * 60}")
        print(f"Running {name} tests...")
        try:
            # Get all test functions from the module
            test_funcs = [f for f in dir(module) if f.startswith('test_') and callable(getattr(module, f))]
            
            for func_name in test_funcs:
                test_func = getattr(module, func_name)
                try:
                    print(f"  - {func_name}... ", end="")
                    test_func()
                    print("PASSED")
                except Exception as e:
                    print(f"FAILED: {str(e)}")
                    all_passed = False
            
        except Exception as e:
            print(f"Error running tests for {name}: {str(e)}")
            all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("ALL TESTS PASSED!")
    else:
        print("SOME TESTS FAILED!")
        
    return all_passed

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)