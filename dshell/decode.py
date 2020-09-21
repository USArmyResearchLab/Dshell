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

# set up logging first, since some third-party libraries would try to
# configure things their own way
import logging
logging.basicConfig(format="%(levelname)s (%(name)s) - %(message)s")
logger = logging.getLogger("decode.py")

# since pypacker handles its own exceptions (loudly), this attempts to keep
# it quiet
from pypacker import pypacker
pypacker.logger.setLevel(logging.CRITICAL)

import dshell.core
from dshell.dshelllist import get_plugins, get_output_modules
from dshell.dshellargparse import DshellArgumentParser
from dshell.output.output import QueueOutputWrapper
from dshell.util import get_output_path

import pcapy

# standard Python library imports
import bz2
import copy
import faulthandler
import gzip
import multiprocessing
import operator
import os
import queue
#import signal
import sys
import tempfile
import zipfile
from collections import OrderedDict
from getpass import getpass
from glob import glob
from importlib import import_module

# plugin_chain will eventually hold the user-selected plugins that packets
# will trickle through.
plugin_chain = []

def feed_plugin_chain(plugin_index, packet_tuple):
    """
    Every packet fed into Dshell goes through this function.
    Its goal is to pass each packet down the chain of selected plugins.
    Each plugin decides whether the packet(s) will proceed to the next
    plugin, i.e. act as a filter.
    """
    global plugin_chain
    (pktlen, pkt, ts) = packet_tuple
    current_plugin = plugin_chain[plugin_index]
    next_plugin_index = plugin_index + 1
    if next_plugin_index >= len(plugin_chain):
        next_plugin_index = None

    # Check the plugin's filter to see if this packet should go any further
    if current_plugin.compiled_bpf and not current_plugin.compiled_bpf.filter(pkt):
        return

    # Begin stepping through the plugin and feeding each handler function in
    # order:
    # raw_handler --> packet_handler -?-> connection_handler (init/blob_handler/close)
    current_plugin._raw_handler(pktlen, pkt, ts)

    # feed any available raw packets to the packet_handler
    while len(current_plugin.raw_packet_queue) > 0:
        rawpacket = current_plugin.raw_packet_queue.pop(0)
        current_plugin._packet_handler(*rawpacket)

    # Check if this plugin handles connections
    # If it doesn't, we can just pass the packet to the next plugin now
    if "_connection_handler" not in current_plugin.members:
        if next_plugin_index:
            while len(current_plugin.packet_queue) > 0:
                packet = current_plugin.packet_queue.pop(0)
                feed_plugin_chain(next_plugin_index, packet.packet_tuple)
        return

    # Connection handlers are a little different.
    # They only enqueue anything when a connection closes or times out.
    while len(current_plugin.packet_queue) > 0:
        packet = current_plugin.packet_queue.pop(0)
        current_plugin._connection_handler(packet)

    # Connections are "passed" to the next plugin by popping off their blobs,
    # then passing all of the packets within.
    # Afterwards, the connection is cleared from the plugin's cache.
    while len(current_plugin.connection_queue) > 0:
        connection = current_plugin.connection_queue.pop(0)
        if next_plugin_index:
            for blob in connection.blobs:
                if not blob.hidden:
                    for packet in blob.all_packets:
                        feed_plugin_chain(next_plugin_index, packet.packet_tuple)
        conn_key = tuple(sorted(connection.addr))
        try:
            # Attempt to clear out the connection, now that it has been handled.
            del current_plugin.connection_tracker[conn_key]
        except KeyError:
            # If the plugin messed with the connection's address, it might
            # fail to clear it.
            # TODO find some way to better handle this scenario
            pass


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

    # Check if the plugin handles connections
    # If it does, close out its open connections and pass the stored packets
    # down the chain.
    if "_connection_handler" in current_plugin.members:
        for connection_handler_out in current_plugin._cleanup_connections():
            if not connection_handler_out:
                continue
            if next_plugin_index:
                for blob in connection_handler_out.blobs:
                    if not blob.hidden:
                        for packet in blob.all_packets:
                            feed_plugin_chain(next_plugin_index, packet.packet_tuple)
    if next_plugin_index:
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
        try:
            # check if this file is actually something decompressable
            openfile.peek(1)
        except OSError as e:
            logger.error("Could not process compressed file {!r}. {!s}".format(filepath, e))
            openfile.close()
            continue
        tfile = tempfile.NamedTemporaryFile(dir=unzipdir, delete=False, prefix=filename)
        for piece in openfile:
            tfile.write(piece)
        tempfiles.append(tfile.name)
        openfile.close()
        tfile.close()
    return tempfiles



def print_plugins(plugins):
    "Print list of plugins with additional info"
    row = "{:<40} {:15} {:<20} {:<20} {:<10} {}"
    print(row.format('module', 'name', 'title', 'type', 'author', 'description'))
    print('-' * 121)
    for name, module in plugins.items():
        print(row.format(module.__module__,
                         name,
                         module.name,
                         module.__class__.__bases__[0].__name__,
                         module.author,
                         module.description))

def main(plugin_args={}, **kwargs):
    global plugin_chain

    # dictionary of all available plugins: {name: module path}
    plugin_map = get_plugins(logger)

    # Attempt to catch segfaults caused when certain linktypes (e.g. 204) are
    # given to pcapy
    faulthandler.enable()

    if not plugin_chain:
        logger.error("No plugin selected")
        sys.exit(1)

    plugin_chain[0].defrag_ip = kwargs.get("defrag", False)

    if kwargs.get("verbose", False):
        logger.setLevel(logging.INFO)
        dshell.core.logger.setLevel(logging.INFO)
        dshell.core.geoip.logger.setLevel(logging.INFO)
        # Activate verbose mode in each of the plugins
        for plugin in plugin_chain:
            plugin.out.set_level(logging.INFO)

    if kwargs.get("allcc", False):
        # Activate all country code (allcc) mode to display all 3 GeoIP2 country
        # codes
        dshell.core.geoip.acc = True

    if kwargs.get("debug", False):
        pypacker.logger.setLevel(logging.WARNING)
        logger.setLevel(logging.DEBUG)
        dshell.core.logger.setLevel(logging.DEBUG)
        dshell.core.geoip.logger.setLevel(logging.DEBUG)
        # Activate debug mode in each of the plugins
        for plugin in plugin_chain:
            plugin.out.set_level(logging.DEBUG)

    if kwargs.get("quiet", False):
        logger.disabled = True
        dshell.core.logger.disabled = True
        dshell.core.geoip.logger.disabled = True
        # Disable logging for each of the plugins
        for plugin in plugin_chain:
            plugin.out.logger.disabled = True

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
            omodule = import_module("dshell.output."+kwargs["omodule"])
            omodule = omodule.obj
            for plugin in plugin_chain:
                oargs['label'] = plugin.__module__
                oomodule = omodule(**oargs)
                if kwargs.get("verbose", False):
                    oomodule.set_level(logging.INFO)
                if kwargs.get("debug", False):
                    oomodule.set_level(logging.DEBUG)
                if kwargs.get("quiet", False):
                    oomodule.logger.disabled = True
                plugin.out = oomodule
        except ImportError as e:
            logger.error("Could not import module named '{}'. Use --list-output flag to see available modules".format(kwargs["omodule"]))
            sys.exit(1)

    # If writing to a file, set for each output module here
    if kwargs.get("outfile", None):
        for plugin in plugin_chain:
            try:
                plugin.out.reset_fh(filename=kwargs["outfile"])
            # Try and catch common exceptions to avoid lengthy tracebacks
            except OSError as e:
                if not self.debug:
                    logger.error(str(e))
                    sys.exit(1)
                else:
                    raise e

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
                multiprocessing.Process(target=process_files, args=([i]), kwargs=kwargs)
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


def process_files(inputs, **kwargs):
    # Iterate over each of the input files
    # For live capture, the "input" would just be the name of the interface
    global plugin_chain

    while len(inputs) > 0:
        input0 = inputs.pop(0)

        # Check if file needs to be decompressed by its file extension
        extension = os.path.splitext(input0)[-1]
        if extension in (".gz", ".bz2", ".zip") and not "interface" in kwargs:
            tempfiles = decompress_file(input0, extension, kwargs.get("unzipdir", tempfile.gettempdir()))
            inputs = tempfiles + inputs
            continue

        for plugin in plugin_chain:
            plugin._prefile(input0)

        if kwargs.get("interface", None):
            # Listen on an interface if the option is set
            try:
                capture = pcapy.open_live(input0, 65536, True, 0)
            except pcapy.PcapError as e:
                # User probably doesn't have permission to listen on interface
                # In any case, print just the error without traceback
                logger.error(str(e))
                sys.exit(1)
        else:
            # Otherwise, read from pcap file(s)
            try:
                capture = pcapy.open_offline(input0)
            except pcapy.PcapError as e:
                logger.error("Could not open '{}': {!s}".format(input0, e))
                continue

        # Try and use the first plugin's BPF as the initial filter
        # The BPFs for other plugins will be applied along the chain as needed
        initial_bpf = plugin_chain[0].bpf
        try:
            if initial_bpf:
                capture.setfilter(initial_bpf)
        except pcapy.PcapError as e:
            if str(e).startswith("no VLAN support for data link type"):
                logger.error("Cannot use VLAN filters for {!r}. Recommend running with --no-vlan argument.".format(input0))
                continue
            elif "syntax error" in str(e) or "link layer applied in wrong context" == str(e):
                logger.error("Could not compile BPF: {!s} ({!r})".format(e, initial_bpf))
                sys.exit(1)
            elif "802.11 link-layer types supported only on 802.11" == str(e):
                logger.error("BPF incompatible with pcap file: {!s}".format(e))
                continue
            else:
                raise e

        # Set the datalink layer for each plugin, based on the pcapy capture.
        # Also compile a pcapy BPF object for each.
        for plugin in plugin_chain:
            # TODO Find way around libpcap bug that segfaults when certain BPFs
            #      are used with certain datalink types
            #      (e.g. datalink=204, bpf="ip")
            plugin.set_link_layer_type(capture.datalink())
            plugin.recompile_bpf()

        # Iterate over the file/interface and pass the packets down the chain
        while True:
            try:
                header, packet = capture.next()
                if header == None and not packet:
                    # probably the end of the capture
                    break
                if kwargs.get("count", 0) and plugin_chain[0].seen_packet_count.value >= kwargs["count"]:
                    # we've reached the maximum number of packets to process
                    break
                pktlen = header.getlen()
                ts = header.getts()
                ts = ts[0] + ts[1] / 1000000.0
                feed_plugin_chain(0, (pktlen, packet, ts))
            except pcapy.PcapError as e:
                estr = str(e)
                eformat = "Error processing '{i}' - {e}"
                if estr.startswith("truncated dump file"):
                    logger.error( eformat.format(i=input0, e=estr) )
                    if kwargs.get("debug", False):
                        logger.exception(e)
                elif estr.startswith("bogus savefile header"):
                    logger.error( eformat.format(i=input0, e=estr) )
                    if kwargs.get("debug", False):
                        logger.exception(e)
                else:
                    raise e
                break

        clean_plugin_chain(0)
        for plugin in plugin_chain:
            try:
                plugin._purge_connections()
            except AttributeError:
                # probably just a packet plugin
                pass
            plugin._postfile()


def main_command_line():
    global plugin_chain
    # dictionary of all available plugins: {name: module path}
    plugin_map = get_plugins(logger)
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
                      action='append', metavar="DECODER",
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
                      action='append', metavar="DECODER",
                      help="Use a specific plugin module")
    parser_short.add_argument('--ebpf', default='', type=str, metavar="BPF",
                        help="Extend existing BPFs with provided input for additional filtering. It will transform input into \"(<original bpf>) and (<ebpf>)\"")
    parser_short.add_argument('-i', '--interface',
                        help="Listen live on INTERFACE instead of reading pcap")
    parser_short.add_argument('-l', '--ls', '--list', action="store_true",
                      help='List all available plugins', dest='list')
    parser_short.add_argument("--lo", "--list-output", action="store_true",
                            help="List available output modules")
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
        # Import ALL of the plugins and print info about them before exiting
        listing_plugins = OrderedDict()
        for name, module in sorted(plugin_map.items(), key=operator.itemgetter(1)):
            try:
                module = import_module(module)
                if not module.DshellPlugin:
                    continue
                module = module.DshellPlugin()
                listing_plugins[name] = module
            except Exception as e:
                logger.error("Could not load {!r}. ({!s})".format(module, e))
                if opts.debug:
                    logger.exception(e)
        print_plugins(listing_plugins)
        sys.exit()

    if opts.listoutput:
        # List available output modules and a brief description
        output_map = get_output_modules(get_output_path(), logger)
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
