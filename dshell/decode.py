#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
This is the core script for running plugins.

It works by grabbing individual packets from a file or interface and feeding
them into a chain of plugins (plugin_chain). Each plugin in the chain
decides if the packet will continue on to the next plugin or just fade away.

In practice, users generally only use one plugin, so the "chain" will only
have one plugin, which is perfectly fine. The chain exists to allow plugins
to alter or filter packets before passing them to more general plugins. For
example, --plugin=country+netflow would pass packets through the country
plugin, and then the netflow plugin. This would allow filtering traffic by
country code before viewing flow data.

Many things go into making this chain run smoothly, however. This includes
reading in user arguments, setting filters, opening files/interfaces, etc. All
of this largely takes place in the main() function.
"""

# standard Python library imports
import bz2
import faulthandler
import gzip
import multiprocessing
import logging
import operator
import os
import queue
import sys
import tempfile
import zipfile
from collections import OrderedDict
from getpass import getpass
from glob import glob
from importlib import import_module
from typing import Iterable

import pcapy
from pypacker.layer12 import ethernet, ppp, pppoe, ieee80211, linuxcc, radiotap, can
from pypacker.layer3 import ip, ip6

import dshell.core
from dshell.api import get_plugin_information
from dshell.core import Packet
from dshell.dshelllist import get_plugins, get_output_modules
from dshell.dshellargparse import DshellArgumentParser
from dshell.output.output import QueueOutputWrapper
from dshell.util import get_output_path
from tabulate import tabulate

logger = logging.getLogger(__name__)


# plugin_chain will eventually hold the user-selected plugins that packets
# will trickle through.
plugin_chain = []


def feed_plugin_chain(plugin_index: int, packet: Packet):
    """
    Every packet fed into Dshell goes through this function.
    Its goal is to pass each packet down the chain of selected plugins.
    Each plugin decides whether the packet(s) will proceed to the next
    plugin, i.e. act as a filter.
    """
    global plugin_chain

    current_plugin = plugin_chain[plugin_index]
    next_plugin_index = plugin_index + 1
    if next_plugin_index >= len(plugin_chain):
        next_plugin_index = None

    # Pass packet into plugin for processing.
    current_plugin.consume_packet(packet)

    # Process produced packets.
    if next_plugin_index:
        for _packet in current_plugin.produce_packets():
            feed_plugin_chain(next_plugin_index, _packet)


def clean_plugin_chain(plugin_index):
    """
    This is called at the end of packet capture.
    It will go through the plugins and attempt to cleanup any connections
    that were not yet closed.
    """
    current_plugin = plugin_chain[plugin_index]
    next_plugin_index = plugin_index + 1
    if next_plugin_index >= len(plugin_chain):
        next_plugin_index = None

    # need to flush even if there are no more plugins in the chain to ensure all packets are processed.
    current_plugin.flush()

    if next_plugin_index:
        for _packet in current_plugin.produce_packets():
            feed_plugin_chain(next_plugin_index, _packet)
        clean_plugin_chain(next_plugin_index)


def decompress_file(filepath, extension, unzipdir):
    """
    Attempts to decompress a provided file and write the data to a temporary
    file. The list of created temporary files is returned.
    """
    filename = os.path.split(filepath)[-1]
    openfiles = []
    logger.debug("Attempting to decompress {!r}".format(filepath))
    if extension == '.gz':
        f = gzip.open(filepath, 'rb')
        openfiles.append(f)
    elif extension == '.bz2':
        f = bz2.open(filepath, 'rb')
        openfiles.append(f)
    elif extension == '.zip':
        pswd = getpass("Enter password for .zip file {!r} [default: none]: ".format(filepath))
        pswd = pswd.encode() # TODO I'm not sure encoding to utf-8 will work in all cases
        try:
            z = zipfile.ZipFile(filepath)
            for z2 in z.namelist():
                f = z.open(z2, 'r', pswd)
                openfiles.append(f)
        except (RuntimeError, zipfile.BadZipFile) as e:
            logger.error("Could not process .zip file {!r}. {!s}".format(filepath, e))
            return []

    tempfiles = []
    for openfile in openfiles:
        with openfile:
            try:
                # check if this file is actually something decompressable
                openfile.peek(1)
            except OSError as e:
                logger.error("Could not process compressed file {!r}. {!s}".format(filepath, e))
                continue
            with tempfile.NamedTemporaryFile(dir=unzipdir, delete=False, prefix=filename) as tfile:
                for piece in openfile:
                    tfile.write(piece)
                tempfiles.append(tfile.name)
    return tempfiles


def print_plugins(plugins):
    """
    Print list of plugins with additional info.
    """
    headers = ['module', 'name', 'title', 'type', 'author', 'description']
    rows = []
    for name, module in sorted(plugins.items()):
        rows.append([
            module.__module__,
            name,
            module.name,
            module.__class__.__bases__[0].__name__,
            module.author,
            module.description,
        ])

    print(tabulate(rows, headers=headers))


def main(plugin_args=None, **kwargs):
    global plugin_chain

    if not plugin_args:
        plugin_args = {}

    # dictionary of all available plugins: {name: module path}
    plugin_map = get_plugins()

    # Attempt to catch segfaults caused when certain linktypes (e.g. 204) are
    # given to pcapy
    faulthandler.enable()

    if not plugin_chain:
        logger.error("No plugin selected")
        sys.exit(1)

    plugin_chain[0].defrag_ip = kwargs.get("defrag", False)

    # Setup logging
    log_format = "%(levelname)s (%(name)s) - %(message)s"
    if kwargs.get("verbose", False):
        log_level = logging.INFO
    elif kwargs.get("debug", False):
        log_level = logging.DEBUG
    elif kwargs.get("quiet", False):
        log_level = logging.CRITICAL
    else:
        log_level = logging.WARNING
    logging.basicConfig(format=log_format, level=log_level)

    # since pypacker handles its own exceptions (loudly), this attempts to keep
    # it quiet
    logging.getLogger("pypacker").setLevel(logging.CRITICAL)

    if kwargs.get("allcc", False):
        # Activate all country code (allcc) mode to display all 3 GeoIP2 country
        # codes
        dshell.core.geoip.acc = True

    dshell.core.geoip.check_file_dates()

    # If alternate output module is selected, tell each plugin to use that
    # instead
    if kwargs.get("omodule", None):
        # Check if any user-defined output arguments are provided
        oargs = {}
        if kwargs.get("oargs", None):
            for oarg in kwargs["oargs"]:
                if '=' in oarg:
                    key, val = oarg.split('=', 1)
                    oargs[key] = val
                else:
                    oargs[oarg] = True
        try:
            # TODO: Create a factory classmethod in the base Output class (e.g. "from_name()") instead.
            omodule = import_module("dshell.output."+kwargs["omodule"])
            omodule = omodule.obj
            for plugin in plugin_chain:
                # TODO: Should we have a single instance of the Output module used by all plugins?
                oomodule = omodule(**oargs)
                plugin.out = oomodule
        except ImportError as e:
            logger.error("Could not import module named '{}'. Use --list-output flag to see available modules".format(kwargs["omodule"]))
            sys.exit(1)

    # If writing to a file, set for each output module here
    if kwargs.get("outfile", None):
        for plugin in plugin_chain:
            plugin.out.reset_fh(filename=kwargs["outfile"])

    # Set nobuffer mode if that's what the user wants
    if kwargs.get("nobuffer", False):
        for plugin in plugin_chain:
            plugin.out.nobuffer = True

    # Set the extra flag for all output modules
    if kwargs.get("extra", False):
        for plugin in plugin_chain:
            plugin.out.extra = True
            plugin.out.set_format(plugin.out.format)

    # Set the BPF filters
    # Each plugin has its own default BPF that will be extended or replaced
    # based on --no-vlan, --ebpf, or --bpf arguments.
    for plugin in plugin_chain:
        if kwargs.get("bpf", None):
            plugin.bpf = kwargs.get("bpf", "")
            continue
        if plugin.bpf:
            if kwargs.get("ebpf", None):
                plugin.bpf = "({}) and ({})".format(plugin.bpf, kwargs.get("ebpf", ""))
        else:
            if kwargs.get("ebpf", None):
                plugin.bpf = kwargs.get("ebpf", "")
        if kwargs.get("novlan", False):
            plugin.vlan_bpf = False

    # Decide on the inputs to use for pcap
    # If --interface is set, ignore all files and listen live on the wire
    # Otherwise, use all of the files and globs to open offline pcap.
    # Recurse through any directories if the command-line flag is set.
    if kwargs.get("interface", None):
        inputs = [kwargs.get("interface")]
    else:
        inputs = []
        inglobs = kwargs.get("files", [])
        infiles = []
        for inglob in inglobs:
            outglob = glob(inglob)
            if not outglob:
                logger.warning("Could not find file(s) matching {!r}".format(inglob))
                continue
            infiles.extend(outglob)
        while len(infiles) > 0:
            infile = infiles.pop(0)
            if kwargs.get("recursive", False) and os.path.isdir(infile):
                morefiles = os.listdir(infile)
                for morefile in morefiles:
                    infiles.append(os.path.join(infile, morefile))
            elif os.path.isfile(infile):
                inputs.append(infile)

    # Process plugin-specific options
    for plugin in plugin_chain:
        for option, args in plugin.optiondict.items():
            if option in plugin_args.get(plugin, {}):
                setattr(plugin, option, plugin_args[plugin][option])
            else:
                setattr(plugin, option, args.get("default", None))
        plugin.handle_plugin_options()


    #### Dshell is ready to read pcap! ####
    for plugin in plugin_chain:
        plugin._premodule()

    # If we are not multiprocessing, simply pass the files for processing
    if not kwargs.get("multiprocessing", False):
        process_files(inputs, **kwargs)
    # If we are multiprocessing, things get more complicated.
    else:
        # Create an output queue, and wrap the 'write' function of each
        # plugins's output module to send calls to the multiprocessing queue
        output_queue = multiprocessing.Queue()
        output_wrappers = {}
        for plugin in plugin_chain:
            qo = QueueOutputWrapper(plugin.out, output_queue)
            output_wrappers[qo.id] = qo
            plugin.out.write = qo.write

        # Create processes to handle each separate input file
        processes = []
        for i in inputs:
            processes.append(
                multiprocessing.Process(target=process_files, args=([i],), kwargs=kwargs)
            )

        # Spawn processes, and keep track of which ones are running
        running = []
        max_writes_per_batch = 50
        while processes or running:
            if processes and len(running) < kwargs.get("process_max", 4):
                # Start a process and move it to the 'running' list
                proc = processes.pop(0)
                proc.start()
                logger.debug("Started process {}".format(proc.pid))
                running.append(proc)
            for proc in running:
                if not proc.is_alive():
                    # Remove finished processes from 'running' list
                    logger.debug("Ended process {} (exit code: {})".format(proc.pid, proc.exitcode))
                    running.remove(proc)
            try:
                # Process write commands in the output queue.
                # Since some plugins write copiously and may block other
                # processes from launching, only write up to a maximum number
                # before breaking and rechecking the processes.
                writes = 0
                while writes < max_writes_per_batch:
                    wrapper_id, args, kwargs = output_queue.get(True, 1)
                    owrapper = output_wrappers[wrapper_id]
                    owrapper.true_write(*args, **kwargs)
                    writes += 1
            except queue.Empty:
                pass

        output_queue.close()

    for plugin in plugin_chain:
        plugin._postmodule()


# Maps datalink type reported by pcapy to a pypacker packet class.
datalink_map = {
    1: ethernet.Ethernet,
    9: ppp.PPP,
    51: pppoe.PPPoE,
    105: ieee80211.IEEE80211,
    113: linuxcc.LinuxCC,
    127: radiotap.Radiotap,
    204: ppp.PPP,
    227: can.CAN,
    228: ip.IP,
    229: ip6.IP6,
}


def read_packets(input: str, interface=False, bpf=None, count=None) -> Iterable[dshell.Packet]:
    """
    Yields packets from input pcap file or device.

    :param str input: device or pcap file path
    :param bool interface: Whether input is a device.
    :param str bpf: Optional bpf filter.
    :param int count: Optional max count of packets to read before exiting.

    :yields: packets defined by pypacker.
        NOTE: Timestamp and frame id are added to packet for convenience.
    """

    if interface:
        # Listen on an interface if the option is set
        try:
            capture = pcapy.open_live(input, 65536, True, 0)
        except pcapy.PcapError as e:
            # User probably doesn't have permission to listen on interface
            # In any case, print just the error without traceback
            logger.error(str(e))
            return
    else:
        # Otherwise, read from pcap file(s)
        try:
            capture = pcapy.open_offline(input)
        except pcapy.PcapError as e:
            logger.error("Could not open '{}': {!s}".format(input, e))
            return

    # TODO: We may want to allow all packets to go through and then allow the plugin to filter
    #   them out in feed_plugin_chain().
    #   That way our frame_id won't be out of sync from skipped packets.
    # Try and use the first plugin's BPF as the initial filter
    # The BPFs for other plugins will be applied along the chain as needed
    try:
        if bpf:
            capture.setfilter(bpf)
    except pcapy.PcapError as e:
        if str(e).startswith("no VLAN support for data link type"):
            logger.error("Cannot use VLAN filters for {!r}. Recommend running with --no-vlan argument.".format(input))
            return
        elif "syntax error" in str(e) or "link layer applied in wrong context" == str(e):
            logger.error("Could not compile BPF: {!s} ({!r})".format(e, bpf))
            return
        elif "802.11 link-layer types supported only on 802.11" == str(e):
            logger.error("BPF incompatible with pcap file: {!s}".format(e))
            return
        else:
            raise e

    # Set the datalink layer for each plugin, based on the pcapy capture.
    # Also compile a pcapy BPF object for each.
    datalink = capture.datalink()
    for plugin in plugin_chain:
        # TODO Find way around libpcap bug that segfaults when certain BPFs
        #      are used with certain datalink types
        #      (e.g. datalink=204, bpf="ip")
        plugin.link_layer_type = datalink
        plugin.recompile_bpf()

    # Get correct pypacker class based on datalink layer.
    packet_class = datalink_map.get(datalink, ethernet.Ethernet)

    logger.info(f"Datalink: {datalink} - {packet_class.__name__}")

    # Iterate over the file/interface and yield Packet objects.
    frame = 1  # Start with 1 because Wireshark starts with 1.
    while True:
        try:
            header, packet_data = capture.next()
            if header is None and not packet_data:
                # probably the end of the capture
                break
            if count and frame - 1 >= count:
                # we've reached the maximum number of packets to process
                break

            # Add timestamp and frame id to packet object for convenience.
            pktlen = header.getlen()
            s, us = header.getts()
            ts = s + us / 1000000.0

            # Wrap packet in dshell's Packet class.
            packet = dshell.Packet(pktlen, packet_class(packet_data), ts, frame=frame)
            frame += 1

            yield packet

        except pcapy.PcapError as e:
            estr = str(e)
            eformat = "Error processing '{i}' - {e}"
            if estr.startswith("truncated dump file"):
                logger.error(eformat.format(i=input, e=estr))
                logger.debug(e, exc_info=True)
            elif estr.startswith("bogus savefile header"):
                logger.error(eformat.format(i=input, e=estr))
                logger.debug(e, exc_info=True)
            else:
                raise
            break


# TODO: The use of kwargs makes it difficult to understand what arguments the function accept
#   and difficult to follow the code flow.
def process_files(inputs, **kwargs):
    # Iterate over each of the input files
    # For live capture, the "input" would just be the name of the interface
    global plugin_chain
    interface = kwargs.get("interface", False)
    count = kwargs.get("count", None)
    # Try and use the first plugin's BPF as the initial filter
    # The BPFs for other plugins will be applied along the chain as needed
    bpf = plugin_chain[0].bpf

    while len(inputs) > 0:
        input0 = inputs.pop(0)

        # Check if file needs to be decompressed by its file extension
        extension = os.path.splitext(input0)[-1]
        if extension in (".gz", ".bz2", ".zip") and "interface" not in kwargs:
            tempfiles = decompress_file(input0, extension, kwargs.get("unzipdir", tempfile.gettempdir()))
            inputs = tempfiles + inputs
            continue

        for plugin in plugin_chain:
            plugin._prefile(input0)

        for packet in read_packets(input0, interface=interface, bpf=bpf, count=count):
            feed_plugin_chain(0, packet)

        clean_plugin_chain(0)
        for plugin in plugin_chain:
            try:
                plugin._purge_connections()
            except AttributeError:
                # probably just a packet plugin
                pass
            plugin._postfile()


# TODO: Separate some of this logic outside of this function so we can call
#   dshell as a library.
def main_command_line():
    # Since plugin_chain contains the actual plugin instances we have to make sure
    # we reset the global plugin_chain so multiple runs don't affect each other.
    # (This was necessary to call this function through a python script.)
    # TODO: Should plugin_chain be a list of plugin classes instead of instances?
    global plugin_chain
    plugin_chain = []

    # dictionary of all available plugins: {name: module path}
    plugin_map = get_plugins()
    # dictionary of plugins that the user wants to use: {name: object}
    active_plugins = OrderedDict()

    # The main argument parser. It will have every command line option
    # available and should be used when actually parsing
    parser = DshellArgumentParser(
        usage="%(prog)s [options] [plugin options] file1 file2 ... fileN",
        add_help=False)
    parser.add_argument('-c', '--count', type=int, default=0,
                      help='Number of packets to process')
    parser.add_argument('--debug', action="store_true",
                      help="Show debug messages")
    parser.add_argument('-v', '--verbose', action="store_true",
                      help="Show informational messages")
    parser.add_argument('-acc', '--allcc', action="store_true",
                      help="Show all 3 GeoIP2 country code types (represented_country/registered_country/country)")
    parser.add_argument('-d', '-p', '--plugin', dest='plugin', type=str,
                      action='append', metavar="PLUGIN",
                      help="Use a specific plugin module. Can be chained with '+'.")
    parser.add_argument('--defragment', dest='defrag', action='store_true',
                      help='Reconnect fragmented IP packets')
    parser.add_argument('-h', '-?', '--help', dest='help',
                      help="Print common command-line flags and exit", action='store_true',
                      default=False)
    parser.add_argument('-i', '--interface', default=None, type=str,
                        help="Listen live on INTERFACE instead of reading pcap")
    parser.add_argument('-l', '--ls', '--list', action="store_true",
                      help='List all available plugins', dest='list')
    parser.add_argument('-r', '--recursive', dest='recursive', action='store_true',
                      help='Recursively process all PCAP files under input directory')
    parser.add_argument('--unzipdir', type=str, metavar="DIRECTORY",
                      default=tempfile.gettempdir(),
                      help='Directory to use when decompressing input files (.gz, .bz2, and .zip only)')

    multiprocess_group = parser.add_argument_group("multiprocessing arguments")
    multiprocess_group.add_argument('-P', '--parallel', dest='multiprocessing', action='store_true',
                      help='Handle each file in separate parallel processes')
    multiprocess_group.add_argument('-n', '--nprocs', type=int, default=4,
                      metavar='NUMPROCS', dest='process_max',
                      help='Define max number of parallel processes (default: 4)')

    filter_group = parser.add_argument_group("filter arguments")
    filter_group.add_argument('--bpf', default='', type=str,
                        help="Overwrite all BPFs and use provided input. Use carefully!")
    filter_group.add_argument('--ebpf', default='', type=str, metavar="BPF",
                        help="Extend existing BPFs with provided input for additional filtering. It will transform input into \"(<original bpf>) and (<ebpf>)\"")
    filter_group.add_argument("--no-vlan", action="store_true", dest="novlan",
                        help="Ignore packets with VLAN headers")

    output_group = parser.add_argument_group("output arguments")
    output_group.add_argument("--lo", "--list-output", action="store_true",
                            help="List available output modules",
                            dest="listoutput")
    output_group.add_argument("--no-buffer", action="store_true",
                            help="Do not buffer plugin output",
                            dest="nobuffer")
    output_group.add_argument("-x", "--extra", action="store_true",
                            help="Appends extra data to all plugin output.")
    # TODO Figure out how to make --extra flag play nicely with user-only
    #      output modules, like jsonout and csvout
    output_group.add_argument("-O", "--omodule", type=str, dest="omodule",
                            metavar="MODULE",
                            help="Use specified output module for plugins instead of defaults. For example, --omodule=jsonout for JSON output.")
    output_group.add_argument("--oarg", type=str, metavar="ARG=VALUE",
                            dest="oargs", action="append",
                            help="Supply a specific keyword argument to user-defined output module. Only used in conjunction with --omodule. Can be used multiple times for multiple arguments. Not using an equal sign will treat it as a flag and set the value to True. Example: --omodule=alertout --oarg \"timeformat=%%H %%M %%S\"")
    output_group.add_argument("-q", "--quiet", action="store_true",
                            help="Disable logging")
    output_group.add_argument("-W", metavar="OUTFILE", dest="outfile",
                            help="Write to OUTFILE instead of stdout")

    parser.add_argument('files', nargs='*',
                        help="pcap files or globs to process")

    # A short argument parser, meant to only hold the simplified list of
    # arguments for when a plugin is called without a pcap file.
    # DO NOT USE for any serious argument parsing.
    parser_short = DshellArgumentParser(
        usage="%(prog)s [options] [plugin options] file1 file2 ... fileN",
        add_help=False)
    parser_short.add_argument('-h', '-?', '--help', dest='help',
                            help="Print common command-line flags and exit", action='store_true',
                            default=False)
    parser.add_argument('--version', action='version',
                        version="Dshell " + str(dshell.core.__version__))
    parser_short.add_argument('-d', '-p', '--plugin', dest='plugin', type=str,
                      action='append', metavar="PLUGIN",
                      help="Use a specific plugin module")
    parser_short.add_argument('--ebpf', default='', type=str, metavar="BPF",
                        help="Extend existing BPFs with provided input for additional filtering. It will transform input into \"(<original bpf>) and (<ebpf>)\"")
    parser_short.add_argument('-i', '--interface',
                        help="Listen live on INTERFACE instead of reading pcap")
    parser_short.add_argument('-l', '--ls', '--list', action="store_true",
                      help='List all available plugins', dest='list')
    parser_short.add_argument("--lo", "--list-output", action="store_true",
                            help="List available output modules")
    # FIXME: Should this duplicate option be removed?
    parser_short.add_argument("-o", "--omodule", type=str, metavar="MODULE",
                            help="Use specified output module for plugins instead of defaults. For example, --omodule=jsonout for JSON output.")
    parser_short.add_argument('files', nargs='*',
                              help="pcap files or globs to process")

    # Start parsing the arguments
    # Specifically, we want to grab the desired plugin list
    # This will let us add the plugin-specific arguments and reprocess the args
    opts, xopts = parser.parse_known_args()
    if opts.plugin:
        # Multiple plugins can be chained using either multiple instances
        # of -d/-p/--plugin or joining them together with + signs.
        plugins = '+'.join(opts.plugin)
        plugins = plugins.split('+')
        # check for invalid plugins
        for plugin in plugins:
            plugin = plugin.strip()
            if not plugin:
                # User probably mistyped '++' instead of '+' somewhere.
                # Be nice and ignore this minor infraction.
                continue
            if plugin not in plugin_map:
                parser_short.epilog = "ERROR! Invalid plugin provided: '{}'".format(plugin)
                parser_short.print_help()
                sys.exit(1)
            # While we're at it, go ahead and import the plugin modules now
            # This can probably be done further down the line, but here is
            # just convenient
            plugin_module = import_module(plugin_map[plugin])
            # Handle multiple instances of same plugin by appending number to
            # end of plugin name. This is used mostly to separate
            # plugin-specific arguments from each other
            if plugin in active_plugins:
                i = 1
                plugin = plugin + str(i)
                while plugin in active_plugins:
                    i += 1
                    plugin = plugin[:-(len(str(i-1)))] + str(i)
            # Add copy of plugin object to chain and add to argument parsers
            # TODO: Use class attributes for class related things like name, description, optionsdict
            #   This way we don't have to initialize the plugin at this point and fixes a lot of the
            #   issues that arise that come from dealing with a singleton.
            active_plugins[plugin] = plugin_module.DshellPlugin()
            plugin_chain.append(active_plugins[plugin])
            parser.add_plugin_arguments(plugin, active_plugins[plugin])
            parser_short.add_plugin_arguments(plugin, active_plugins[plugin])
        opts, xopts = parser.parse_known_args()

    if xopts:
        for xopt in xopts:
            logger.warning('Could not understand argument {!r}'.format(xopt))

    if opts.help:
        # Just print the full help message and exit
        parser.print_help()
        print("\n")
        for plugin in plugin_chain:
            print("############### {}".format(plugin.name))
            print(plugin.longdescription)
            print("\n")
            print('Default BPF: "{}"'.format(plugin.bpf))
        print("\n")
        sys.exit()

    if opts.list:
        try:
            print_plugins(get_plugin_information())
        except ImportError as e:
            logger.error(e, exc_info=opts.debug)
        sys.exit()

    if opts.listoutput:
        # List available output modules and a brief description
        output_map = get_output_modules(get_output_path())
        for modulename in sorted(output_map):
            try:
                module = import_module("dshell.output."+modulename)
                module = module.obj
            except Exception as e:
                etype = e.__class__.__name__
                logger.debug("Could not load {} module. ({}: {!s})".format(modulename, etype, e))
            else:
                print("\t{:<25} {}".format(modulename, module._DESCRIPTION))
        sys.exit()

    if not opts.plugin:
        # If a plugin isn't provided, print the short help message
        parser_short.epilog = "Select a plugin to use with -d or --plugin"
        parser_short.print_help()
        sys.exit()

    if not opts.files and not opts.interface:
        # If no files are provided, print the short help message
        parser_short.epilog = "Include a pcap file to get started. Use --help for more information."
        parser_short.print_help()
        sys.exit()

    # Process the plugin-specific args and set the attributes within them
    plugin_args = {}
    for plugin_name, plugin in active_plugins.items():
        plugin_args[plugin] = {}
        args_and_attrs = parser.get_plugin_arguments(plugin_name, plugin)
        for darg, dattr in args_and_attrs:
            value = getattr(opts, darg)
            plugin_args[plugin][dattr] = value

    main(plugin_args=plugin_args, **vars(opts))


if __name__ == "__main__":
    main_command_line()
