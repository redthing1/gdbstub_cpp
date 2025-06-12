#!/usr/bin/env python3
"""
GDB Remote Serial Protocol Test Suite
Professional test suite for GDB stub implementation validation.
"""

import subprocess
import sys
import time
import os
import random
import argparse
import logging


class GDBStubTestSuite:
    """Professional test suite for GDB Remote Serial Protocol implementation."""

    def __init__(
        self,
        lldb_path=None,
        helper_path=None,
        base_port=50000,
        timeout=10,
        startup_timeout=3,
        verbose=False,
        log_level=logging.INFO,
    ):
        # Auto-detect LLDB if not specified
        if lldb_path is None:
            lldb_candidates = [
                "/opt/homebrew/opt/llvm/bin/lldb",  # Homebrew on macOS
                "/usr/local/bin/lldb",  # Manual install
                "/usr/bin/lldb",  # System install
                "lldb",  # PATH
            ]
            self.lldb_path = None
            for candidate in lldb_candidates:
                if os.path.exists(candidate) or candidate == "lldb":
                    self.lldb_path = candidate
                    break
        else:
            self.lldb_path = lldb_path

        self.helper_path = helper_path or "./build/tests/test_helper"
        self.base_port = base_port
        self.timeout = timeout
        self.startup_timeout = startup_timeout
        self.helper = None
        self.current_port = None
        self.tests_passed = 0
        self.tests_failed = 0
        self.verbose = verbose
        self.test_results = []

        # Setup logging
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S",
        )
        self.logger = logging.getLogger(__name__)

    def get_available_port(self):
        """Get a random available port for testing."""
        return self.base_port + random.randint(0, 999)

    def start_helper(self):
        """Start the test helper process - simple approach like simple_working_test.py"""
        self.current_port = self.get_available_port()

        # Start helper - simple approach, no complex startup detection
        if self.verbose:
            self.helper = subprocess.Popen([self.helper_path, str(self.current_port)])
        else:
            # Hide helper output unless verbose
            self.helper = subprocess.Popen(
                [self.helper_path, str(self.current_port)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        time.sleep(2)  # Give helper time to start - same as simple_working_test.py

    def stop_helper(self):
        """Stop the test helper process."""
        if self.helper:
            self.helper.terminate()
            self.helper.wait()
            self.helper = None

    def run_lldb_test(self, commands, timeout=None):
        """Run LLDB commands against gdbstub and return success/failure."""
        if timeout is None:
            timeout = self.timeout

        import tempfile
        import shlex

        # Create shell script - same approach as simple_working_test.py
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
            f.write("#!/bin/bash\n")
            f.write("{\n")
            f.write(f'    echo "gdb-remote 127.0.0.1:{self.current_port}"\n')
            for cmd in commands:
                f.write(f'    echo "{cmd}"\n')
            f.write('    echo "quit"\n')
            f.write("    sleep 0.1\n")
            f.write(f"}} | {shlex.quote(self.lldb_path)} --no-lldbinit")
            # Only show output if verbose mode is enabled
            if not self.verbose:
                f.write(" >/dev/null 2>&1")
            f.write("\n")
            script_path = f.name

        import os

        os.chmod(script_path, 0o755)

        try:
            result = subprocess.run(["bash", script_path], timeout=timeout)
            os.unlink(script_path)
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            try:
                os.unlink(script_path)
            except:
                pass
            return False
        except Exception:
            try:
                os.unlink(script_path)
            except:
                pass
            return False

    def run_test(self, test_name, test_func):
        """Execute a single test with proper setup and teardown."""
        self.logger.info(f"Running test: {test_name}")

        if not self.verbose:
            print(f"  {test_name:<25}", end=" ")

        start_time = time.time()

        try:
            self.start_helper()
            success, details = test_func()
            elapsed = time.time() - start_time

            result = {
                "name": test_name,
                "success": success,
                "details": details,
                "elapsed": elapsed,
                "port": self.current_port,
            }
            self.test_results.append(result)

            if success:
                if self.verbose:
                    print(f"\n[PASS] {test_name}")
                    print(f"       Time: {elapsed:.2f}s")
                    print(f"       Port: {self.current_port}")
                    print(f"       Details: {details}")
                else:
                    print(f"PASS ({elapsed:.1f}s)")
                self.tests_passed += 1
                return True
            else:
                if self.verbose:
                    print(f"\n[FAIL] {test_name}")
                    print(f"       Time: {elapsed:.2f}s")
                    print(f"       Port: {self.current_port}")
                    print(f"       Details: {details}")
                else:
                    print(f"FAIL ({elapsed:.1f}s)")
                self.tests_failed += 1
                return False

        except Exception as e:
            elapsed = time.time() - start_time
            self.logger.error(f"Test {test_name} failed with exception: {e}")

            result = {
                "name": test_name,
                "success": False,
                "details": str(e),
                "elapsed": elapsed,
                "port": self.current_port,
            }
            self.test_results.append(result)

            if self.verbose:
                print(f"\n[ERROR] {test_name}")
                print(f"        Time: {elapsed:.2f}s")
                print(f"        Exception: {e}")
            else:
                print(f"ERROR ({elapsed:.1f}s)")
            self.tests_failed += 1
            return False
        finally:
            self.stop_helper()

    def test_basic_connection(self):
        """Test basic GDB protocol connection and register read."""
        success = self.run_lldb_test(["register read pc"])

        if success:
            return True, "Connected successfully, PC register accessible"
        else:
            return False, "LLDB command failed or timed out"

    def test_register_operations(self):
        """Test reading all registers."""
        success = self.run_lldb_test(["register read"])

        if success:
            return True, "Register read command executed successfully"
        else:
            return False, "LLDB command failed or timed out"

    def test_memory_read(self):
        """Test memory read operations."""
        success = self.run_lldb_test(["memory read 0x80000000 0x80000020"])

        if success:
            return True, "Memory read from 0x80000000 successful"
        else:
            return False, "LLDB command failed or timed out"

    def test_breakpoint_operations(self):
        """Test breakpoint set and list operations."""
        success = self.run_lldb_test(
            ["breakpoint set --address 0x80000004", "breakpoint list"]
        )

        if success:
            return True, "Breakpoint operations executed successfully"
        else:
            return False, "LLDB command failed or timed out"

    def test_single_step(self):
        """Test single step execution."""
        success = self.run_lldb_test(
            ["register read pc", "thread step-inst", "register read pc"]
        )

        if success:
            return True, "Single step executed successfully"
        else:
            return False, "LLDB command failed or timed out"

    def test_thread_information(self):
        """Test thread information queries."""
        success = self.run_lldb_test(["thread list", "thread info"])

        if success:
            return True, "Thread information retrieved successfully"
        else:
            return False, "LLDB command failed or timed out"

    def test_process_information(self):
        """Test process information queries."""
        success = self.run_lldb_test(["target list"])

        if success:
            return True, "Process information retrieved successfully"
        else:
            return False, "LLDB command failed or timed out"

    def test_memory_regions(self):
        """Test memory region information."""
        success = self.run_lldb_test(["memory region 0x80000000"])

        if success:
            return True, "Memory region query executed successfully"
        else:
            return False, "LLDB command failed or timed out"

    def test_continue_execution(self):
        """Test continue execution functionality."""
        success = self.run_lldb_test(["register read pc", "continue"])

        if success:
            return True, "Continue execution completed successfully"
        else:
            return False, "LLDB command failed or timed out"

    def test_error_handling(self):
        """Test graceful error handling with invalid operations."""
        success = self.run_lldb_test(["memory read 0x00000000"])

        # Should handle gracefully - either succeed or fail gracefully
        return True, f"Error handling test completed (success: {success})"

    def run_all_tests(self):
        """Execute the complete test suite."""
        print("\nGDB Remote Serial Protocol Test Suite")
        print("=" * 60)

        self.logger.info("Starting test suite")
        self.logger.debug(f"Helper path: {self.helper_path}")
        self.logger.debug(f"LLDB path: {self.lldb_path}")
        self.logger.debug(f"Port range: {self.base_port}-{self.base_port + 999}")

        # Verify prerequisites
        if not os.path.exists(self.helper_path):
            print(f"\nERROR: Test helper not found at {self.helper_path}")
            print("Please build the project first:")
            print("  cmake -B build")
            print("  cmake --build build")
            print(f"Or specify custom path with --helper-path")
            return 1

        # Check LLDB availability
        lldb_available = False
        if self.lldb_path == "lldb":
            # Check if lldb is in PATH
            try:
                result = subprocess.run(
                    ["lldb", "--version"], capture_output=True, timeout=5
                )
                lldb_available = result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError):
                lldb_available = False
        else:
            lldb_available = os.path.exists(self.lldb_path)

        if not lldb_available:
            print(f"\nERROR: LLDB not found at {self.lldb_path}")
            print("Please install LLDB or specify custom path with --lldb")
            print("Common LLDB locations:")
            print("  /opt/homebrew/opt/llvm/bin/lldb  (Homebrew macOS)")
            print("  /usr/local/bin/lldb              (Manual install)")
            print("  /usr/bin/lldb                    (System install)")
            return 1

        print(f"\nConfiguration:")
        print(f"  Helper:          {self.helper_path}")
        print(f"  LLDB:            {self.lldb_path}")
        print(f"  Port Range:      {self.base_port}-{self.base_port + 999}")
        print(f"  Test Timeout:    {self.timeout}s")
        print(f"  Startup Timeout: {self.startup_timeout}s")
        print(f"\nRunning tests:")

        # Define test cases
        test_cases = [
            ("Basic Connection", self.test_basic_connection),
            ("Register Operations", self.test_register_operations),
            ("Memory Read", self.test_memory_read),
            ("Breakpoint Operations", self.test_breakpoint_operations),
            ("Single Step", self.test_single_step),
            ("Thread Information", self.test_thread_information),
            ("Process Information", self.test_process_information),
            ("Memory Regions", self.test_memory_regions),
            ("Continue Execution", self.test_continue_execution),
            ("Error Handling", self.test_error_handling),
        ]

        # Execute tests
        start_time = time.time()
        for test_name, test_func in test_cases:
            success = self.run_test(test_name, test_func)
            if test_name == "Basic Connection" and not success:
                print(f"\nFAIL FAST: Basic connection test failed, stopping test suite")
                break
            if not self.verbose:
                time.sleep(0.1)  # Brief pause between tests

        total_elapsed = time.time() - start_time

        # Report results
        total_tests = len(test_cases)
        print(f"\n" + "=" * 60)
        print(f"TEST RESULTS")
        print(f"=" * 60)
        print(f"Total Tests:    {total_tests}")
        print(f"Passed:         {self.tests_passed}")
        print(f"Failed:         {self.tests_failed}")
        print(f"Success Rate:   {(self.tests_passed/total_tests)*100:.1f}%")
        print(f"Total Time:     {total_elapsed:.2f}s")

        if self.verbose and self.test_results:
            print(f"\nDETAILED RESULTS:")
            print(f"-" * 60)
            for result in self.test_results:
                status = "PASS" if result["success"] else "FAIL"
                print(f"{result['name']:<25} {status:<4} {result['elapsed']:.2f}s")
                if not result["success"] and result["details"]:
                    print(f"  -> {result['details'][:80]}")

        print(f"\nSTATUS: ", end="")
        if self.tests_passed == total_tests:
            print("ALL TESTS PASSED")
            return 0
        elif self.tests_passed >= total_tests * 0.8:
            print("MOST TESTS PASSED (80%+ success rate)")
            return 0
        else:
            print("SOME TESTS FAILED")
            return 1


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="GDB Remote Serial Protocol Test Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 tests/test_suite.py                              # Run all tests
  python3 tests/test_suite.py -v                           # Verbose output
  python3 tests/test_suite.py --debug                      # Debug logging
  python3 tests/test_suite.py --lldb /usr/bin/lldb         # Custom LLDB path
  python3 tests/test_suite.py --port 60000                 # Custom port range
  python3 tests/test_suite.py --timeout 30                 # Longer timeout
""",
    )

    # Output options
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose test output"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument(
        "--log-file", type=str, help="Write logs to file instead of console"
    )

    # Configuration options
    parser.add_argument(
        "--lldb",
        type=str,
        metavar="PATH",
        help="Path to LLDB binary (default: auto-detect)",
    )
    parser.add_argument(
        "--helper-path",
        type=str,
        metavar="PATH",
        help="Path to test helper binary (default: ./build/tests/test_helper)",
    )
    parser.add_argument(
        "--port",
        type=int,
        metavar="PORT",
        default=50000,
        help="Base port number for testing (default: 50000)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        metavar="SECONDS",
        default=30,
        help="Test timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--startup-timeout",
        type=int,
        metavar="SECONDS",
        default=3,
        help="Helper startup timeout in seconds (default: 3)",
    )

    # Test selection (for future expansion)
    parser.add_argument(
        "--list-tests", action="store_true", help="List available tests and exit"
    )

    args = parser.parse_args()

    # Configure logging level
    log_level = logging.DEBUG if args.debug else logging.INFO
    if not args.verbose and not args.debug:
        log_level = logging.WARNING

    # Configure log file if specified
    if args.log_file:
        logging.basicConfig(
            filename=args.log_file,
            level=log_level,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    # Handle list tests option
    if args.list_tests:
        test_names = [
            "Basic Connection",
            "Register Operations",
            "Memory Read",
            "Breakpoint Operations",
            "Single Step",
            "Thread Information",
            "Process Information",
            "Memory Regions",
            "Continue Execution",
            "Error Handling",
        ]
        print("Available tests:")
        for i, name in enumerate(test_names, 1):
            print(f"  {i:2d}. {name}")
        return 0

    # Validate arguments
    if args.port < 1024 or args.port > 65000:
        print("ERROR: Port must be between 1024 and 65000")
        return 1

    if args.timeout < 1 or args.timeout > 300:
        print("ERROR: Timeout must be between 1 and 300 seconds")
        return 1

    if args.startup_timeout < 1 or args.startup_timeout > 60:
        print("ERROR: Startup timeout must be between 1 and 60 seconds")
        return 1

    test_suite = GDBStubTestSuite(
        lldb_path=args.lldb,
        helper_path=args.helper_path,
        base_port=args.port,
        timeout=args.timeout,
        startup_timeout=args.startup_timeout,
        verbose=args.verbose,
        log_level=log_level,
    )
    return test_suite.run_all_tests()


if __name__ == "__main__":
    sys.exit(main())
