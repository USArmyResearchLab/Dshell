#!/usr/bin/env python

# pylint: disable-msg=C0103,E501

import copy
import dshell
import glob
import gzip
import logging
import optparse
import os
import output
import sys
import tempfile
import traceback
import util
import zipfile
try:
    import pcap
except ImportError:
    pcap = None
    print 'pcap not available: decoders requiring pcap are not usable'


def import_module(name=None, silent=False, search=None):
    if search is None:
        search = {}
    try:
        # we will first check search[name] for the module
        # else split foo.bar:baz to get from foo.bar import baz
        # else split dotted path to perform a 'from foo import bar' operation
        try:
            module = search[name]  # a -> from search[a] import a
        except KeyError:
            # a.b.c from a.b import c
            module, name = name.split('.')[:-1], name.split('.')[-1]
            if module:
                module = '.'.join(module)
            else:
                module = name
        path = None
        if os.path.sep in module:  # was a full path to a decoder given?
            path, module = os.path.dirname(module), os.path.basename(module)
        # print module,name
        if path:
            sys.path.append(path)
        obj = __import__(module, fromlist=[name])
        if path:
            sys.path.remove(path)
        if 'dObj' in dir(obj) or 'obj' in dir(obj):
            return obj
        elif name in dir(obj):
            obj = getattr(obj, name)
            if 'dObj' in dir(obj) or 'obj' in dir(obj):
                return obj
    except Exception as err:
        if not silent:
            sys.stderr.write(
                "Error '%s' loading module %s\n" % (str(err), module))
    return False


def setDecoderPath(decoder_path):
    '''set the base decoder path,
        add it to sys.path for importing,
        and walk it to return all subpaths'''
    paths = []
    paths.append(decoder_path)  # append base path first
    # walk decoder directories an add to sys.path
    for root, dirs, files in os.walk(decoder_path):
        # skip hidden dirs like .svn
        [dirs.remove(d) for d in dirs if d.startswith('.')]
        for d in sorted(dirs):
            paths.append(os.path.join(root, d))
    return paths  # return the paths we found


def getDecoders(decoder_paths):
    ''' find all decoders and map decoder to import.path.decoder
    expect common prefix to start with basepath'''
    import_base = os.path.commonprefix(decoder_paths).split(
        os.path.sep)[:-1]  # keep last part as base
    decoders = {}
    for path in decoder_paths:
        # split path and trim off part before base
        import_path = path.split(os.path.sep)[len(import_base):]
        for f in glob.iglob("%s/*.py" % path):
            name = os.path.splitext(os.path.basename(f))[0]
            if name != '__init__':  # skip package stubs
                # build topdir.path...module name from topdir/dir.../file
                decoders[name] = '.'.join(import_path + [name])
    return decoders


def printDecoders(decoder_map, silent=True):
    '''Print list of decoders with additional info'''
    dList = []
    FS = '  %-40s %-30s %-10s %s %1s  %s'
    for name, module in sorted(decoder_map.iteritems()):
        try:
            try:
                decoder = import_module(module, silent).dObj
            except Exception as exc:
                print "Exception loading module '%s': %s" % (module, exc)
                continue
            # get the type of decoder it is
            dtype = 'RAW'
            if 'IP' in dir(decoder):
                dtype = 'IP '
            if 'UDP' in dir(decoder):
                dtype = 'UDP'
            if 'TCP' in dir(decoder):
                dtype = 'TCP'
            dList.append(FS % (
                module, decoder.name,
                decoder.author,
                dtype, '+' if decoder.chainable else '',
                decoder.description))
        except:  # :-(
            pass

    print FS % ('module', 'name', 'author', '   ', ' ', 'desc')
    print FS % ('-' * 40, '-' * 30, '-' * 10, '---', '-', '-' * 50)
    for d in sorted(dList):
        print d


def readInFilter(fname):
    '''Read in a BPF filter provided by a command line argument'''
    filter = ''
    tmpfd = open(fname, 'r')
    for line in tmpfd:
        if '#' in line:
            # keep \n for visual output sanity
            line = line.split('#')[0] + '\n'
        filter += line
    tmpfd.close()

    return filter


def decode_live(out, options, decoder, decoder_args, decoder_options):
    # set decoder options
    initDecoderOptions(decoder, out, options, decoder_args, decoder_options)

    if 'preModule' in dir(decoder):
        decoder.preModule()

    # give the interface name to the decoder
    decoder.input_file = options.interface
    stats = None
    if options.verbose:
        log('Attempting to listen on %s' % options.interface)
    try:

        if not pcap:
            raise NotImplementedError("raw capture support not implemented")
        decoder.capture = pcap.pcap(options.interface, 65535, True)
        if decoder.filter:
            decoder.capture.setfilter(decoder.filter)
        while not options.count or decoder.count < options.count:
            # use dispatch so we can handle signals
            decoder.capture.dispatch(1, decoder.decode)
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        log(str(exc), level=logging.ERROR)

    if 'cleanConnectionStore' in dir(decoder):
        decoder.cleanConnectionStore()

    if 'postModule' in dir(decoder):
        decoder.postModule()


def expandCompressedFile(fname, verbose, tmpdir):
    ''' Expand a file compressed with gzip, bzip2, or zip.
    Only handles zip files with 1 file. Need to add handling
    for zip files containing multiple pcap files.'''
    try:
        # print fname
        ext = os.path.splitext(fname)[1]
        if verbose:
            log('+Attempting to process %s compressed file' % (ext))
        if ext == '.gz':
            f = gzip.open(fname, 'rb')
        elif ext == '.bz2':
            f = bz2.BZ2File(fname, 'r')
        elif ext == '.zip':
            print "Enter password for .zip file [default:none]:",
            pswd = raw_input()
            z = zipfile.ZipFile(fname)
            f = z.open(z.namelist()[0], 'r', pswd)
        else:
            log('+Error decompressing %s' % (fname), level=logging.ERROR)
            return

        h = tempfile.NamedTemporaryFile(dir=tmpdir, delete=False)
        if verbose:
            log('+Temp directory: %s' % (tempfile.gettempdir()))
            log('+Expanding to tempfile %s' % (h.name))

        for line in f.readlines():
            h.write(line)
        h.close()
        f.close()
        return h.name
    except:
        return None


# This is a support function for the code in main() that supports
# recursive directory crawling when looking for pcap files to parse
# This function recurses through a directory structure, applying
# the wildcard (if any) from the command line.  If no wildcard
# is specified, then all files are included.
def addFilesFromDirectory(inputs, curDir, wildcard='*'):
    # STEP 1: Add files matching wildcard from current directory...

    # concatenate into path
    full_path = os.path.join(curDir, wildcard)
    inputs.extend(glob.glob(full_path))

    # STEP 2: Recurse into child directories
    for path in os.listdir(curDir):
        fullDir = os.path.join(curDir, path)

        if os.path.isdir(fullDir):
            addFilesFromDirectory(inputs, fullDir, wildcard)


# The default OptionParser will raise an error when it encounters an option that
# it doesn't understand.  By creating a new option parser, dshellOptionParser,
# we can ignore the unknown options (read: Module specific options)
class dshellOptionParser(optparse.OptionParser):

    def error(self, msg):
        pass

    # create options for all loaded decoders
    def add_decoder_options(self, d):
        if d.subDecoder:
            # if we have a subdecoder, recurse down until we don't
            self.add_decoder_options(d.subDecoder)
        try:
            if d.optiondict:
                group = optparse.OptionGroup(
                    self, "%s decoder options" % d.name)
                for argname, optargs in d.optiondict.iteritems():
                    optname = "%s_%s" % (d.name, argname)
                    group.add_option("--" + optname, dest=optname, **optargs)
                self.add_option_group(group)
        except:
            raise  # :-(

    # pass thru to parse_args, but add in kwargs
    def parse_args(self, args, **kwargs):
        try:
            options, args = optparse.OptionParser.parse_args(self, args)
            options.__dict__.update(kwargs)
        except UnboundLocalError:
            # probably missing a value for an argument, e.g. 'decode -d'
            # without a decoder
            self.print_help()
            return None, None
        return options, args

        # Fix for handling unknown options (e.g. decoder-specific options)
        # reference:
        # http://stackoverflow.com/questions/1885161/how-can-i-get-optparses-optionparser-to-ignore-invalid-arguments
    def _process_args(self, largs, rargs, values):
        while rargs:
            try:
                optparse.OptionParser._process_args(self, largs, rargs, values)
            except (optparse.BadOptionError, optparse.AmbiguousOptionError) as exc:
                largs.append(exc.opt_str)


def printDecoderBriefs(decoders):
    """Prints a brief overview of a decoder when using --help with a decoder"""
    print
    for d in decoders.values():
        print 'Module name:', d.name
        print '=' * 20
        if d.longdescription:
            print d.longdescription
        else:
            print d.description
        print 'Default filter: %s' % (d.filter)
    return


def initDecoderOptions(decoder, out, options, decoder_args, decoder_options):
    """
    pass global config to decoder
    """

    # recurse from the bottom of the chain to the top
    if decoder.subDecoder:
        initDecoderOptions(
            decoder.subDecoder, out, options, decoder_args, decoder_options)

    # give the decoder the output object if the decoder doesn't pick one
    # or if an output object is specified via command line options
    if not decoder.out or options.output != 'output':
        decoder.out = out
    else:
        # initialize the decoder's custom output using the channels from the
        # global
        # provide global output module under alternate name
        decoder.globalout = out
        # decoder.out.__init__(fh=out.fh) #re-init the decoder
        try:
            # If the decoder's default output doesn't have a filehandle set,
            # use the user provided one
            if decoder.out.fh == sys.stdout:
                decoder.out.fh = out.fh
        except AttributeError:
            # A filehandle doesn't always exist, such as with QueueOutput
            pass
        if not decoder.out.sessionwriter:
            decoder.out.sessionwriter = out.sessionwriter
        if not decoder.out.pcapwriter:
            decoder.out.pcapwriter = out.pcapwriter
    # set the logger
    decoder.out.logger = logging.getLogger(decoder.name)

    # set output format string, or reset to default
    # do not override --oformat specified string
    if decoder.format and not options.oformat:
        decoder.out.setformat(decoder.format)

    # set verbosity
    decoder.verbose = options.verbose
    if options.debug:
        # debug() is already taken, and _DEBUG might already be set
        decoder._DEBUG = options.debug

    # override decoder BPF
    if options.bpf != None:
        decoder.filter = options.bpf

    # override decoder filterfn
    if options.nofilterfn:
        decoder.filterfn = lambda addr: True

    # read BPF from file
    if options.filefilter != None:
        try:
            tmpbpf = readInFilter(options.filefilter)
        except:
            log("Invalid tcpdump filter file: %s" %
                (options.filefilter), level=logging.ERROR)
            return

        decoder.filter = tmpbpf

    # extend bpf filter if necessary
    if options.ebpf != None:
        ebpf = options.ebpf
        if not decoder.filter:
            decoder.filter = ebpf
        elif ebpf.startswith('or '):
            decoder.filter = decoder.filter + ' ' + ebpf
        else:
            decoder.filter = decoder.filter + ' and ' + ebpf

    # do we change the layer-2 decoder for raw capture
    if options.layer2:
        import dpkt
        decoder.l2decoder = eval('dpkt.' + options.layer2)

    # strip extra layers?
    if options.striplayers:
        decoder.striplayers = int(options.striplayers)

    if not options.novlan and not(decoder.filter.startswith('vlan')):
        if decoder.filter:
            decoder.filter = '( ' + decoder.filter + \
                ' ) or ( vlan and ( ' + decoder.filter + ' ) )'
        else:
            decoder.filter = ''  # fix for null filter case

    # pass args and config file to decoder
    decoder.parseArgs(decoder_args, decoder_options)

    log('Using module ' + repr(decoder))


def main(*largs, **kwargs):
    global log
    bin_path = os.environ['BINPATH']
    sys.path.insert(0, bin_path)
    # get map of name to module import path
    decoder_map = getDecoders(setDecoderPath(os.environ['DECODERPATH']))

    # The main argument parser. It will have every command line option
    # available and should be used when actually parsing
    parser = dshellOptionParser(
        usage="usage: %prog [options] [decoder options] file1 file2 ... filen [-- [decoder args]+]",
        version="%prog " + str(dshell.__version__), add_help_option=False)
    # A short argument parser, meant to only hold the shorter list of
    # arguments for when a decoder is called without a pcap file. DO
    # NOT USE for any serious argument parsing.
    parser_short = dshellOptionParser(
        usage="usage: %prog [options] [decoder options] file1 file2 ... filen [-- [decoder args]+]",
        version="%prog " + str(dshell.__version__), add_help_option=False)
    parser.add_option('-h', '-?', '--help', dest='help',
                      help="Print common command-line flags and exit", action='store_true',
                      default=False)
    parser_short.add_option('-h', '-?', '--help', dest='help',
                            help="Print common command-line flags and exit", action='store_true',
                            default=False)
    parser.add_option('-d', '--decoder', dest="decoder",
                      action='append', help="Use a specific decoder module")
    parser.add_option('-l', '--ls', '--list', action="store_true",
                      help='List all available decoders', dest='list')
    parser.add_option(
        '-C', '--config', dest='config', help='specify config.ini file')
    parser.add_option('--tmpdir', dest='tmpdir', type='string', default=tempfile.gettempdir(),
                      help='alternate temp directory (for use when processing compressed pcap files)')
    parser.add_option('-r', '--recursive', dest='recursive', action='store_true',
                      help='recursively process all PCAP files under input directory')

    group = optparse.OptionGroup(parser, "Multiprocessing options")
    group.add_option('-p', '--parallel', dest='parallel',
                     action='store_true', help='process multiple files in parallel')
    group.add_option('-t', '--threaded', dest='threaded',
                     action='store_true', help='run multiple decoders in parallel')
    group.add_option('-n', '--nprocs', dest='numprocs', type='int',
                     default=4, help='number of simultaneous processes')
    parser.add_option_group(group)

    # decode-pcap specific options
    group = optparse.OptionGroup(parser, "Input options")
    group.add_option('-i', '--interface', dest='interface',
                     default=None, help='listen live on INTERFACE')
    group.add_option('-c', '--count', dest='count', type='int',
                     help='number of packets to process', default=0)
    group.add_option('-f', '--bpf', dest='bpf',
                     help='replace default decoder filter (use carefully)')
    group.add_option('--nofilterfn', dest='nofilterfn',
                     action="store_true", help='Set filterfn to pass-thru')
    group.add_option('-F', dest='filefilter',
                     help='Use filefilter as input for the filter expression.  An additional expression given on the command line is ignored.')
    group.add_option(
        '--ebpf', dest='ebpf', help='BPF filter to exclude traffic, extends other filters')
    group.add_option('--no-vlan', dest='novlan', action="store_true",
                     help='do not examine traffic which has VLAN headers present')
    group.add_option('--layer2', dest='layer2', default='ethernet.Ethernet',
                     help='select the layer-2 protocol module')
    group.add_option('--strip', dest='striplayers', default=0,
                     help='extra data-link layers to strip')
    parser.add_option_group(group)

    group = optparse.OptionGroup(parser_short, "Input options")
    group.add_option('-i', '--interface', dest='interface',
                     default=None, help='listen live on INTERFACE')
    group.add_option('-c', '--count', dest='count', type='int',
                     help='number of packets to process', default=0)
    group.add_option('-f', '--bpf', dest='bpf',
                     help='replace default decoder filter (use carefully)')
    group.add_option('--nofilterfn', dest='nofilterfn',
                     action="store_true", help='Set filterfn to pass-thru')
    group.add_option('-F', dest='filefilter',
                     help='Use filefilter as input for the filter expression.  An additional expression given on the command line is ignored.')
    group.add_option(
        '--ebpf', dest='ebpf', help='BPF filter to exclude traffic, extends other filters')
    group.add_option('--no-vlan', dest='novlan', action="store_true",
                     help='do not examine traffic which has VLAN headers present')
    group.add_option('--layer2', dest='layer2', default='ethernet.Ethernet',
                     help='select the layer-2 protocol module')
    group.add_option('--strip', dest='striplayers', default=0,
                     help='extra data-link layers to strip')
    parser_short.add_option_group(group)

    group = optparse.OptionGroup(parser, "Output options")
    group.add_option('-o', '--outfile', dest='outfile', help='write output to the file OUTFILE. Additional output can be set with KEYWORD=VALUE,...\n' +
                     '\tmode=<w: write (default), a: append, noclobber: do not overwrite, use a  a OUTFILE.1 (.2,.3) file if file(s) exists\n' +
                     '\tpcap=PCAPFILE to write packets to a PCAP file\n' +
                     '\tsession=SESSION to write session text\n' +
                     '\tdirection=data direction to write (c,s,both,split)')
    group.add_option('--nobuf', help='turn off output buffering', dest='nobuffer',
                     action='store_true', default=False)
    group.add_option('-w', '--session', dest='session',
                     help='write session file, same as -o session=')
    group.add_option('-W', '--pcap', dest='pcap', default=None,
                     help='output decoded packets to PCAP (same as -o pcap=....)')
    group.add_option('--db', dest='db', default=None,
                     help='output to db. Supply "config=file" or "param=...,param=..." ')
    group.add_option(
        '--oformat', dest='oformat', help='define the output format')
    group.add_option('-x', '--extra', dest='oextra',
                     action='store_true', help='output a lot of extra information')
    group.add_option('-O', '--output', dest='output', default=None,
                     help='Use a custom output module. Supply "modulename,option=value,..."')
    parser.add_option_group(group)

    group = optparse.OptionGroup(parser, "Logging options")
    group.add_option('-L', '--logfile', dest="logfile", help="log to file")
    group.add_option('--debug', action="store_true", dest="debug",
                     help="debug logging (debug may also affect decoding behavior)")
    group.add_option('-v', '--verbose', action="store_true",
                     dest="verbose", help="verbose logging")
    group.add_option('-q', '--quiet', action="store_true",
                     dest="quiet", help="practically zero logging")
    parser.add_option_group(group)

    group = optparse.OptionGroup(parser_short, "Logging options")
    group.add_option('-L', '--logfile', dest="logfile", help="log to file")
    group.add_option('--debug', action="store_true", dest="debug",
                     help="debug logging (debug may also affect decoding behavior)")
    group.add_option(
        '-v', '--verbose', action="store_true", dest="verbose", help="verbose logging")
    group.add_option('-q', '--quiet', action="store_true",
                     dest="quiet", help="practically zero logging")
    parser_short.add_option_group(group)

    # [decoder][option]=value dict of decoder options, set by config file
    decoder_options = {}
    decoder_args = []
    args = []
    extra_args = False
    for x in largs:
        if x == '--':
            extra_args = True
            continue
        if extra_args:
            decoder_args.append(x)
        else:
            args.append(x)

    # parse basic options and crdate the options object
    options = parser.parse_args(args, **kwargs)[0]

    if options == None:
        print "\nError processing provided arguments"
        return

    # dump list
    if options.list:
        printDecoders(decoder_map, not options.debug)
        return

    # parse config file, updating the options and decoder_options dicts
    if options.config:
        try:
            import ConfigParser
            config = ConfigParser.ConfigParser()
            config.read(options.config)
            for s in config.sections():
                # this is the main section, set the options
                if s.lower() == 'dshell':
                    for k, v in config.items(s, raw=True):
                        if k in options.__dict__:
                            options.__dict__[k] = v
        except:
            raise  # :-(

    # are we a thread outputting to a queue?
    if 'queue' in options.__dict__:
        out = output.QueueOutput(options.queue)
    # if not, parse output args
    else:
        outfile = None
        outkw = {}

        # set output file (and other args if -o filename,key=val...)
        if options.outfile:
            outfile, outkw = util.strtok(options.outfile)
        if options.nobuffer:
            outkw.update(nobuffer=True)
        # output extra?
        if options.oextra:
            outkw.update(extra=True)
        # set session writer?
        if options.session:
            outkw.update(session=options.session)
        # add default pcap writer?
        if options.pcap:
            outkw.update(pcap=options.pcap)
        # use database?
        if options.db:
            a, kw = util.strtok(options.db, as_list=True)
            # add output options
            kw.update(outkw)
            out = output.DBOutput(*a, **kw)
        # if not db mode and no out module specd
        # use default output lib to get default module
        elif not options.output:
            options.output = 'output'
        # init output module
        if options.output:
            # parse output arglist (-O module,args..,k=val...)
            a, kw = util.strtok(options.output, as_list=True)
            kw.update(outkw)  # set output options
            if outfile:
                # set filename arg if -o given (can also be first arg in module
                # arglist)
                kw.update(file=outfile)
            outmod = import_module(name=os.path.basename(a[0]))  # load module
            if outmod:
                # pass remaining args and keyword args to init object
                out = outmod.obj(*a[1:], **kw)

        # set the output format
        if options.oformat != None:
            out.setformat(options.oformat)

    # set global log functions
    out.logger = logging.getLogger('dshell')
    log = out.log

    # start up the logger
    if options.debug:
        level = logging.DEBUG
    elif options.verbose:
        level = logging.INFO
    elif options.quiet:
        level = logging.FATAL
    else:
        level = logging.WARNING
    logging.basicConfig(filename=options.logfile, level=level)

    decoders = {}
    decoderNames = set()
    # check for a decoder
    if options.decoder != None:
        # single decoder or came from config file
        if type(options.decoder) == str:
            options.decoder = util.strtok(
                options.decoder, as_list=True)[0]  # make it a list
        # we have a list of decoders
        for dnames in options.decoder:
            chain = dnames.split('+')
            # last module does not have a subdecoder
            module = chain.pop()
            try:
                module, n = module.split(':', 1)
            except:
                n = None
            m = import_module(module, search=decoder_map)
            if m:
                # create copy in case we import multiple times under different
                # names
                dObj = copy.copy(m.dObj)
                if n:
                    dObj.name = n
            else:
                dObj = None
            try:
                decoderNames.add(dObj.name)
            except AttributeError:
                decoderNames.add(module)
            # walk up the chain, setting sub-decoders
            while chain:
                subObj = dObj
                module = chain.pop()
                try:
                    module, n = module.split(':', 1)
                except:  # :-(
                    n = None
                m = import_module(module, search=decoder_map)
                if m:
                    dObj = copy.copy(m.dObj)
                    if n:
                        dObj.name = n
                else:
                    dObj = None
                try:
                    decoderNames.add(dObj.name)
                except AttributeError:
                    decoderNames.add(module)
                if dObj and dObj.chainable:
                    dObj.subDecoder = subObj
                elif dObj:
                    sys.stderr.write("Error %s is not chainable\n" % module)
            # insert the top decoder in the dict
            if dObj:
                decoders[dObj.name] = dObj

    # save option dict
    options_dict = options.__dict__.copy()

    # add in options for loaded decoders and subdecoders
    for d in decoders.itervalues():
        parser.add_decoder_options(d)
    for d in decoders.itervalues():
        parser_short.add_decoder_options(d)

    # reparse args to handle decoder options
    optionerror = False
    try:
        options, args = parser.parse_args(args, **kwargs)
    except:
        optionerror = True

    # replace base options
    options.__dict__.update(options_dict)

    # look for name_option keys and put them in decoder_options[name][option]
    for k, v in options.__dict__.iteritems():
        for decName in decoderNames:
            try:
                n = k.split(decName + '_', 1)[1]
                decoder_options.setdefault(decName, {}).setdefault(n, v)
            except IndexError:
                continue

    # reparse config file to handle decoder options
    if options.config:
        for s in config.sections():
            # set the options for loaded decoders if they are present in the
            # config file
            if s.lower() in decoder_options:
                for k, v in config.items(s, raw=True):
                    if k in decoder_options[s]:  # if this is a valid option
                        if v.isdigit():
                            v = int(v)  # try conversion to int/float
                        elif '.' in v:
                            try:
                                v = float(v)
                            except:
                                pass
                        decoder_options[s][k] = v

    if any(x in ('-h', '-?', '--help') for x in sys.argv[1:]):
            # Print the verbose help message
        parser.print_help()
        printDecoderBriefs(decoders)
        return

    if optionerror or (not args and not options.interface):
        # Print the short help message
        parser_short.print_help()
        printDecoderBriefs(decoders)
        return

        #######################################################################
        # listen live on the interface
        # this will not process any files
    if options.interface != None:
        if len(decoders) != 1:
            print 'Can only run one module live on an interface'
            return

        # handles options and arguments for dumping live on an interface
        decode_live(out, options, dObj, decoder_args, decoder_options)

        # close output
        out.close()

        return
        #######################################################################

    # take all other command line arguments as files to process

    ####################################################
    # Works if directory (e.g. ~/data/) or * (e.g. ~/data/*
    # used on command line.  Does not work for partial
    # wildcards (e.g. ~/data/*.dat) because bash
    # expands wildcards before passing arguments into
    # decode-pcap.py.  Will work if no matches in root of
    # path specified.
    ####################################################
    inputs = []
    for file_path in args:
        # If this argument is a directory and RECURSIVE specified, then add
        # entire directory tree to the list of input files
        if os.path.isdir(file_path) and options.recursive:
            addFilesFromDirectory(inputs, file_path)

        # If a wildcard is specified, then handle accordingly
        elif file_path.find('*') > -1:
            (path, wildcard) = os.path.split(file_path)

            # If just file is specified (no path)
            if len(path) == 0:
                inputs.extend(glob.glob(wildcard))

            # If there is a path, but recursion not specified,
            # then just add matching files from specified dir
            elif not len(path) == 0 and not options.recursive:
                inputs.extend(glob.glob(file_path))

            # Otherwise, recursion specified and there is a directory.
            # Recurse directory and add files
            else:
                addFilesFromDirectory(inputs, path, wildcard)

        # Just a normal file, append to list of inputs
        else:
            inputs.append(file_path)

    if options.parallel or options.threaded:
        import multiprocessing
        procs = []
        q = multiprocessing.Queue()
        kwargs = options.__dict__.copy()  # put parsed base options in kwargs
        kwargs.update(config=None, outfile=None, queue=q)  # pass the q,
        # do not pass the config file or outfile because we handled that here
        for d in decoder_options:  # put pre-parsed decoder options in kwargs
            for k, v in decoder_options[d].items():
                kwargs[d + '_' + k] = v

    # check here to see if we are running in parallel-file mode
    if options.parallel and len(inputs) > 1:
        for f in inputs:
            # create a child process for each input file
            procs.append(
                multiprocessing.Process(target=main, kwargs=kwargs, args=[f]))
        runChildProcs(procs, q, out, numprocs=options.numprocs)

    # check here to see if we are running decoders multithreaded
    elif options.threaded and len(options.decoder) > 1:
        for d in options.decoder:
            # create a child for each decoder
            kwargs.update(decoder=d)
            procs.append(
                multiprocessing.Process(target=main, kwargs=kwargs, args=inputs))
        runChildProcs(procs, q, out, numprocs=options.numprocs)

    # fall through to here (single threaded or child process)
    else:
        #
        # Here is where we use the decoder(s) to process the pcap
        #

        temporaryFiles = []    # used when uncompressing files

        for module in decoders.keys():
            decoder = decoders[module]
            initDecoderOptions(
                decoder, out, options, decoder_args, decoder_options)

            # If the decoder has a preModule function, will execute it now
            decoder.preModule()

            for input_file in inputs:
                # Decoder-specific options may be seen as input files
                # Skip anything starts with "--"
                if input_file[:2] == '--':
                    continue

                # Recursive directory processing is handled elsewhere,
                # so we should only be dealing with files at this point.
                if os.path.isdir(input_file):
                    continue

                log('+Processing file %s' % input_file)

                # assume the input_file is not compressed
                # Allows the processing of .pcap files that are compressed with
                # gzip, bzip2, or zip. Writes uncompressed file to a
                # NamedTemporaryFile and unlinks the file once it is no longer
                # needed. Might consider using mkstemp() since this implementation
                # requires Python >= 2.6.
                try:
                    exts = ['.gz', '.bz2', '.zip']
                    if os.path.splitext(input_file)[1] not in exts:
                        pcapfile = input_file

                    else:
                        # we have a compressed file
                        tmpfile = expandCompressedFile(
                            input_file, options.verbose, options.tmpdir)
                        temporaryFiles.append(tmpfile)
                        pcapfile = tmpfile
                except:
                    if options.verbose:
                        sys.stderr.write(
                            '+Error processing file %s' % (input_file))
                    continue

                # give the decoder access to the input filename
                # motivation: run a decoder against a large number of pcap
                #             files and have the decoder print the filename
                #             so you can go straight to the pcap file for
                #             further analysis
                decoder.input_file = input_file

                # Check to see if the decoder has a preFile function
                # This will be called before the decoder processes each
                # input file
                decoder.preFile()

                try:
                    if not pcap:
                        raise NotImplementedError(
                            "pcap support not implemented")
                    decoder.capture = pcap.pcap(pcapfile)
                    if decoder.filter:
                        decoder.capture.setfilter(decoder.filter)
                    while not options.count or decoder.count < options.count:
                        try:
                            # read next packet and break on EOF
                            ts, pkt = decoder.capture.next()
                        except:
                            break  # no data
                        decoder.decode(ts, pkt)
                except KeyboardInterrupt:
                    raise
                except:
                    traceback.print_exc()

                if options.verbose:
                    log('+Done processing %s' % (input_file))

                # call that decoder's processFile()
                decoder.postFile()

            # check to see if the decoder is using the Messages class
            # if so, we need to clean up the connection store to
            # purge any unfinished connections
            if 'cleanConnectionStore' in dir(decoder):
                decoder.cleanConnectionStore()

            # Check to see if the decoder has a postModule function
            # A postModule function will be called when the module
            # has finished running against all of the input files
            if 'postModule' in dir(decoder):
                decoder.postModule()

        # remove any temporary files that were created during execution
        for tmpfile in temporaryFiles:
            if options.verbose:
                log('+Unlinking %s' % (tmpfile))
            os.unlink(tmpfile)

    # close output
    out.close()
    return


def runChildProcs(procs, q, out, numprocs=4):
    import Queue
    running = []
    # while we still have processes to spawn or running
    while procs or running:
        if procs and len(running) < numprocs:
            proc = procs.pop(0)
            proc.start()
            out.log('started %d' % proc.pid, level=logging.INFO)
            running.append(proc)
        for proc in running:
            if not proc.is_alive():  # see if it finished
                out.log('%d exited (%d)' %
                        (proc.pid, proc.exitcode), level=logging.INFO)
                running.remove(proc)
        try:  # get from the output queue until empty
            while True:
                m, args, kw = q.get(True, 1)  # method, listargs, kwargs
                out.dispatch(m, *args, **kw)  # dispatch to method
        except Queue.Empty:
            pass  # q empty


if __name__ == '__main__':
    try:
        main(*sys.argv[1:])
    except KeyboardInterrupt:
        sys.exit(0)
