__author__ = 'Dante Signal31'

import os.path
import shutil
import tempfile
import unittest
import uuid

import bin.generate_dshellrc as dshellrc
import lib.rc_configuration as rc_configuration


def _get_parent_folder(filepath):
    """ Get folder that contains the one where reference file is in.

    :param filepath: Reference file name.
    :type filepath: str
    :return: Absolute path to parent folder.
    :rtype: str
    """
    absolute_filepath = os.path.abspath(filepath)
    file_folder = os.path.dirname(absolute_filepath)
    parent_file_folder = os.path.dirname(file_folder)
    return parent_file_folder


class TestGenerateDshellrc(unittest.TestCase):

    def test_create_lib_folders(self):
        with TemporaryDirectory() as temporary_folder:
            dshellrc._create_lib_folders(temporary_folder)
            python_version_name = dshellrc._get_python_version_name()
            folder_created = os.path.exists(os.path.join(temporary_folder,
                                                         'lib',
                                                         python_version_name,
                                                         'site-packages'))
            self.assertTrue(folder_created,
                            msg="lib/pythonX/site-packages not created.")

    def test_create_bash_files(self):
        dshell_folder = _get_parent_folder(__file__)
        temporary_folder = _get_temporary_name()
        with ClonedWorkingEnvironment(dshell_folder, temporary_folder):
            configuration = rc_configuration.RcConfiguration(temporary_folder)
            dshellrc._create_lib_folders(configuration.base_folder)
            dshellrc._create_bash_files(configuration=configuration,
                                        bash_completion=False)
            self._assert_files_created(configuration)
            self._assert_files_content_ok(configuration)

    def _assert_files_created(self, configuration):
        files_to_check = [".dshellrc", "dshell", "dshell-decode"]
        for file_ in files_to_check:
            file_path = os.path.join(configuration.base_folder, file_)
            file_created = os.path.exists(file_path)
            self.assertTrue(file_created,
                            msg="One of the files was not created: {0}".format(file_path))

    def _assert_files_content_ok(self, configuration):
        #                  filename: text to check.
        files_to_check = {"dshell": ["/bin/bash --rcfile", ],
                          "dshell-decode": ["source", ],
                          ".dshellrc": ["export PATH=$BINPATH:$PATH", ]}
        for file_, texts_to_check in files_to_check.items():
            file_content = _get_file_content(base_folder=configuration.base_folder,
                                             file_to_read=file_)
            tested_text_inside = _check_all_texts_inside(main_text=file_content,
                                                         texts_to_check=texts_to_check)
            self.assertTrue(tested_text_inside,
                            msg="{0} has not proper content".format(file_))

    def test_dshellrc_creation_with_bash_completion(self):
        dshell_folder = _get_parent_folder(__file__)
        temporary_folder = _get_temporary_name()
        with ClonedWorkingEnvironment(folder_to_clone=dshell_folder,
                                      destination_folder=temporary_folder):
            configuration = rc_configuration.RcConfiguration(temporary_folder)
            texts_to_check = ["export PATH=$BINPATH:$PATH",
                              configuration.dshellrc]
            dshellrc._create_dshellrc(configuration=configuration,
                                      bash_completion=True)
            file_content = _get_file_content(base_folder=configuration.base_folder,
                                             file_to_read=".dshellrc")
            tested_text_inside = _check_all_texts_inside(main_text=file_content,
                                                         texts_to_check=texts_to_check)
            self.assertTrue(tested_text_inside,
                            msg="{0} has not proper content".format(".dshellrc"))


def _get_file_content(base_folder, file_to_read):
    """ Open a text file and return its content.

    :param base_folder: File folder.
    :type base_folder: str
    :param file_to_read: Name of the file to open.
    :type file_to_read: str
    :return: Text content of the opened file.
    :rtype: str
    """
    file_path = os.path.join(base_folder, file_to_read)
    with open(file_path, "r") as created_file:
        file_content = "".join(created_file.readlines())
    return file_content


def _check_all_texts_inside(main_text, texts_to_check):
    """ Check if all texts fragments are present inside main text.

    :param main_text: Text to search into.
    :type main_text: str
    :param texts_to_check: Text fragments to look for.
    :type texts_to_check: list
    :return: True if all fragments are found inside main text, False if not.
    :rtype: bool
    """
    for fragment in texts_to_check:
        if fragment not in main_text:
            break
    else:
        return True
    return False


class TemporaryDirectory(object):
    """  Context manager to create temporary directories.

    Python 3 has tempfile.TemporaryDirectory() but Python 2.7 doesn't. This
    context manager tries to emulate Python3's TemporaryDirectory() behaviour.
    """

    def __init__(self):
        self.temporary_directory = ""

    def __enter__(self):
        self.temporary_directory = tempfile.mkdtemp()
        return self.temporary_directory

    def __exit__(self, exc_type, exc_val, exc_tb):
        shutil.rmtree(self.temporary_directory)
        if exc_type is None:
            return True
        else:
            return False


class ClonedWorkingEnvironment(object):
    """  Replicate all files and subdirs in given folder to an also given
    destination folder.

    Destination folder should not exists when cloning.
    """

    def __init__(self, folder_to_clone, destination_folder):
        """
        :param folder_to_clone: Absolute path to original folder.
        :type folder_to_clone: str
        :param destination_folder: Absolute path to destination folder.
        :type destination_folder: str
        """
        self._folder_to_clone = folder_to_clone
        self._destination_folder = destination_folder

    def __enter__(self):
        shutil.copytree(src=self._folder_to_clone, dst=self._destination_folder)

    def __exit__(self, exc_type, exc_val, exc_tb):
        shutil.rmtree(self._destination_folder)
        if exc_type is None:
            return True
        else:
            return False


def _get_temporary_name():
    """
    :return: Random name for a folder in temp dir.
    :rtype: str
    """
    filename = str(uuid.uuid4())
    temp_folder = tempfile.gettempdir()
    temporary_pathname = os.path.join(temp_folder, filename)
    return temporary_pathname


if __name__ == '__main__':
    unittest.main()
