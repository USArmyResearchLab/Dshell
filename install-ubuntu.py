#!/usr/bin/env python

from pkgutil import iter_modules
from subprocess import call


DSHELL_DEPENDENCIES = {
    "Crypto": "crypto",
    "dpkt": "dpkt",
    "IPy": "ipy",
    "pcap": "pypcap"
}


def _get_installed_packages():
    """ Get all packages available in this system.

    :return: Package list.
    :rtype: list
    """
    installed = [pkg[1] for pkg in iter_modules()]
    return installed


def _get_missing_packages(installed, dependencies):
    """ Get packages needed but not already installed.

    :param installed: List of installed packages.
    :type installed: list
    :param dependencies: List of needed packages.
    :type dependencies: dict
    :return: Missing package list.
    :rtype: list
    """
    missing_packages = []
    for module, pkg in dependencies.items():
        if module not in installed:
            print("dshell requires {}".format(module))
            missing_packages.append("python-{}".format(pkg))
        else:
            print("{} is installed".format(module))
    return missing_packages


def _install_missing_packages(missing_packages):
    """ Install packages from Ubuntu repositories.

    :param missing_packages: List of packages to install.
    :type missing_packages: list
    :return: None
    """
    cmd = ["sudo", "apt-get", "install"] + missing_packages
    print(" ".join(cmd))
    call(cmd)


def _install_dshell():
    """ Run external "make all".

    :return: None
    """
    call(["make", "all"])


def main():
    installed_packages = _get_installed_packages()
    missing_packages = _get_missing_packages(installed=installed_packages,
                                             dependencies=DSHELL_DEPENDENCIES)
    if missing_packages is not None:
        _install_missing_packages(missing_packages)
    _install_dshell()


if __name__ == "__main__":
    main()
