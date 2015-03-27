#!/usr/bin/env python
"""
 run_tests

 Programmed by: Dante Signal 31

 email: dante.signal31@gmail.com

 Run Dshell unittest test cases.
"""

import sys
import unittest

DEFAULT_TEST_DIR = "tests"


def load_all_tests():
    tests = unittest.defaultTestLoader.discover(DEFAULT_TEST_DIR)
    return tests


def load_tests_by_pattern(pattern):
    pattern_with_globs = "%s" % (pattern,)
    tests = unittest.defaultTestLoader.discover("tests",
                                                pattern=pattern_with_globs)
    return tests


def run_tests(tests):
    runner = unittest.TextTestRunner(stream=sys.stdout, verbosity=1)
    runner.run(tests)


def run_functional_tests(pattern=None):
    print("Running tests...")
    if pattern is None:
        tests = load_all_tests()
    else:
        tests = load_tests_by_pattern(pattern)
    run_tests(tests)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        run_functional_tests()
    else:
        run_functional_tests(pattern=sys.argv[1])
