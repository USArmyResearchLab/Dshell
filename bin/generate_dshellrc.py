#!/usr/bin/python

import argparse
import os
import sys


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


def _add_folder_to_python_path(folder):
    """  Include given folder in Python path.

    :param folder: Absolute path to folder include.
    :type folder: str
    :return: None
    """
    sys.path.append(folder)

# Importing sibling packages means messing with path if your script
# is not called from another script one level up:
#       http://stackoverflow.com/questions/6323860/sibling-package-imports
_parent_folder = _get_parent_folder(__file__)
_add_folder_to_python_path(_parent_folder)

import lib.rc_configuration as rc_configuration


def _create_lib_folders(base_folder):
    """ Create installation Dshell folders.

    :param base_folder: Dshell folder absolute path.
    :type base_folder: str
    :return: None
    """
    python_version_name = _get_python_version_name()
    try:
        os.makedirs(os.path.join(base_folder, 'lib', python_version_name,
                                 'site-packages'))
    except Exception as e:
        print e


def _get_python_version_name():
    """ Get python version name, for instance: "Python.2.7"

    :return: Python version name.
    :rtype: str
    """
    python_main_version = ".".join(sys.version.split('.', 3)[:2]).split(' ')[0]
    python_version_name = ".".join(["python", python_main_version])
    return python_version_name


def _load_environment_variables(configuration):
    """  Get configuration envvars and envsetup and return the in a dictionary.

    :param configuration: Dshell shell configuration.
    :type configuration: lib.rc_configuration.RcConfiguration
    :return: Envvars and envsetup packet in a single dictionary.
    :rtype: dict
    """
    envdict = {}
    envdict.update(configuration.envvars)
    envdict.update(configuration.envsetup)
    return envdict


def _create_bash_files(configuration, bash_completion):
    """ Create Dshell bash files and populate them with default content.

    :param configuration: Dshell shell configuration.
    :type configuration: lib.rc_configuration.RcConfiguration
    :param bash_completion: Dshell console should have bash completion?
    :type bash_completion: bool
    :return: None
    """
    _create_dshellrc(configuration=configuration,
                     bash_completion=bash_completion)
    _create_dshell_launcher(configuration)
    _create_dshell_decode(configuration)
    pass


def _create_dshellrc(configuration, bash_completion):
    """ Create Dshell bashrc files and populate it with default content.

    :param configuration: Dshell shell configuration.
    :type configuration: lib.rc_configuration.RcConfiguration
    :param bash_completion: Dshell console should have bash completion?
    :type bash_completion: bool
    :return: None
    """
    env = _create_variable_exports_strings(configuration)
    _create_dshellrc_file(configuration=configuration,
                          bash_completion=bash_completion,
                          env_string=env)


def _create_variable_exports_strings(configuration):
    """ Create lines with needed bash variables exports.

    :param configuration: Dshell shell configuration.
    :type configuration: lib.rc_configuration.RcConfiguration
    :return: List with bash variable exports lines.
    :rtype: list
    """
    ps1_string = ['export PS1="`whoami`@`hostname`:\w Dshell> "']
    envvars_strings = ["export {0}={1}".format(k, v)
                       for k, v in configuration.envvars.items()]
    envsetup_strings = ["export {0}={1}".format(k, v)
                        for k, v in configuration.envsetup.items()]
    env = ps1_string + envvars_strings + envsetup_strings
    return env


def _create_dshellrc_file(configuration, bash_completion, env_string):
    """ Create Dshell bashrc file and populate it with default content and
     with bash variables exports lines.

    :param configuration: Dshell shell configuration.
    :type configuration: lib.rc_configuration.RcConfiguration
    :param bash_completion: Dshell console should have bash completion?
    :type bash_completion: bool
    :param env_string: Variables export lines
    :type env_string: list
    :return: None
    """
    file_path = os.path.join(configuration.base_folder, ".dshellrc")
    with open(file_path, 'w') as outfd:
        outfd.write("\n".join(env_string))
        if bash_completion:
            outfd.write("\n\n")
            outfd.write(configuration.dshellrc)


def _create_dshell_launcher(configuration):
    """ Create Dshell launcher and populate it with default content.

    :param configuration: Dshell shell configuration.
    :type configuration: lib.rc_configuration.RcConfiguration
    :return: None
    """
    file_path = os.path.join(configuration.base_folder, "dshell")
    with open(file_path, 'w') as outfd:
        outfd.write('#!/bin/bash\n')
        outfd.write('/bin/bash --rcfile {0}/.dshellrc\n'.format(configuration.base_folder))


def _create_dshell_decode(configuration):
    """ Create Dshell decode launcher and populate it with default content.

    :param configuration: Dshell shell configuration.
    :type configuration: lib.rc_configuration.RcConfiguration
    :return: None
    """
    file_path = os.path.join(configuration.base_folder, "dshell-decode")
    with open(file_path, 'w') as outfd:
        outfd.write('#!/bin/bash\n')
        outfd.write('source {0}/.dshellrc\n'.format(configuration.base_folder))
        outfd.write('decode "$@"')


def _parse_arguments():
    """ Deal with user arguments in a pythonic way. """

    arg_parser = argparse.ArgumentParser(description="Generate Dshell console "
                                                     "environment.\n",
                                         epilog="More info at: "
                                                "<https://github.com/USArmyResearchLab/Dshell>")
    arg_parser.add_argument(dest="cwd", metavar="\"Installation folder\"",
                            type=str, help="Folder where Dshell is installed.")
    # TODO: This next parameter is ever used?
    # Actual Makefile does not include a second argument when it calls
    # generate_dshellrc.py.
    arg_parser.add_argument("-c", "--with_bash_completion",
                            dest="with_bash_completion",
                            action="store_true",
                            default=False,
                            help="Make Dshell have bash completion.")
    return arg_parser.parse_args()


def main():
    _arguments = _parse_arguments()
    configuration = rc_configuration.RcConfiguration(_arguments.cwd)
    _create_lib_folders(configuration.base_folder)
    # TODO: Find out if envdict is really used.
    # I've kept it here to not to break anything because it was in original
    # source code, but I think this variable is doing nothing. I'm going
    # to review the rest of source code and if I don't find any reference
    # to envdict I'm going to remove it from here.
    envdict = _load_environment_variables(configuration)
    _create_bash_files(configuration=configuration,
                       bash_completion=_arguments.with_bash_completion)

if __name__ == '__main__':
    main()
