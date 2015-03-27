__author__ = 'Dante Signal31'

import os
import unittest

import lib.rc_configuration as rc_configuration
import tests.test_bin_generate_dshellrc as test_generate_dshellrc


class TestRcConfiguration(unittest.TestCase):

    def test_assert_path_exists(self):
        """ Test rc_configuration.assert_path_exists decorator. """
        class PathExistsException(Exception):
            def __init__(self):
                pass

        @rc_configuration.assert_path_exists
        def dummy_function(_, path):
            raise PathExistsException()

        existent_path = os.getcwd()
        non_existent_path = test_generate_dshellrc._get_temporary_name()

        with self.assertRaises(PathExistsException):
            dummy_function(None, existent_path)
        with self.assertRaises(rc_configuration.MissingFolderError):
            dummy_function(None, non_existent_path)


if __name__ == '__main__':
    unittest.main()
