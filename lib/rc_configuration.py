__author__ = 'Dante Signal31'

import functools
import os.path
import sys


DSHELLRC_PATHNAME = "etc/dshellrc"


def _get_python_version():
    """
    :return: Python version number.
    :rtype: str
    """
    python_version = '.'.join(sys.version.split('.', 3)[:2]).split(' ')[0]
    return python_version

def assert_path_exists(function):
    """ Decorator to raise an exception if path set in argument does not
    exists.
    """

    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        # Being used as a method decorator, args[0] is "self".
        path_to_check = args[1]
        if not os.path.exists(path_to_check):
            raise MissingFolderError(path_to_check)
        result = function(*args, **kwargs)
        return result
    return wrapper


class RcConfiguration(object):
    """ This class contains Dshell own shell configuration. """

    def __init__(self, base_folder):
        """
        :param base_folder: Absolute path to Dshell installation folder.
        :type base folder: str
        """
        self._base_folder = ""
        self._dshellrc = ""
        # environment variables used by shell and modules
        self._envvars = {'DSHELL': '{}',
                         'DECODERPATH': '{}/decoders',
                         'BINPATH': '{}/bin',
                         'LIBPATH': '{}/lib',
                         'DATAPATH': '{}/share'}
        # further shell environment setup
        self._envsetup = {'LD_LIBRARY_PATH': '$LIBPATH:$LD_LIBRARY_PATH',
                          'PATH': '$BINPATH:$PATH',
                          'PYTHONPATH': '$DSHELL:$LIBPATH:$LIBPATH/output:' +
                                        os.path.join('$LIBPATH', 'python' +
                                                     _get_python_version(),
                                                     'site-packages') +
                                        ':$PYTHONPATH'}
        self.base_folder = base_folder

    @property
    def base_folder(self):
        """ Absolute path to folder where Dshell is installed.

        :return: str
        """
        return self._base_folder

    @base_folder.setter
    @assert_path_exists
    def base_folder(self, path):
        self._base_folder = path
        self._set_envvars(path)
        self._set_dshellrc(path)

    def _set_envvars(self, path):
        """ Configure envvars with a base path.

        :param path: Base path to include en variables' value.
        :type path: str
        :return: None
        """
        self._envvars = {key: value.format(path)
                         for key, value in self._envvars.items()}

    def _set_dshellrc(self, path):
        """ Set dshellrc attribute with etc/dshellrc content.

        :param path: Absolute path to folder where Dshell is installed.
        :type path: str
        :return: None
        """
        dshellrc_pathname = os.path.join(path, DSHELLRC_PATHNAME)
        with open(dshellrc_pathname, "r") as dshellrc_file:
            self._dshellrc = "".join(dshellrc_file.readlines())

    @property
    def envvars(self):
        """ Absolute paths to main Dshell folders.

        This attribute is read-only, the only way to change where the paths
        point to is setting base_folder attribute.

        :return: dict
        """
        return self._envvars

    @property
    def envsetup(self):
        """ Environment variables useful for Dshell setup.

        This attribute is read-only.

        :return: dict
        """
        return self._envsetup

    @property
    def dshellrc(self):
        """ Bashrc configuration for Dshell.

        This attribute is read-only.

        :return: str
        """
        return self._dshellrc


class MissingFolderError(Exception):
    """ Raised when a nonexistent folder has been referenced. """
    def __init__(self, folder_path):
        """
        :param folder_path: Absolute path to missing folder.
        :type folder_path: str
        """
        self.msg = folder_path