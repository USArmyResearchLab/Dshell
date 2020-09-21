"""
Goes through TCP connections and tries to find FTP control channels and
associated data channels. Optionally, it will write out any file data it
sees into a separate directory.

If a data connection is seen, it prints a message indicating the user, pass,
and file requested. If the --ftp_dump flag is set, it also dumps the file into the
--ftp_outdir directory.
"""

import dshell.core
import dshell.util
from dshell.output.alertout import AlertOutput

import os
import re
import sys

# constants for channel type
CTRL_CONN = 0
DATA_CONN = 1

class DshellPlugin(dshell.core.ConnectionPlugin):

    def __init__(self):
        super().__init__(
            name="ftp",
            description="alerts on FTP traffic and, optionally, rips files",
            longdescription="""
Goes through TCP connections and tries to find FTP control channels and
associated data channels. Optionally, it will write out any file data it
sees into a separate directory.

If a data connection is seen, it prints a message indicating the user, pass,
and file requested. If the --ftp_dump flag is set, it also dumps the file into the
--ftp_outdir directory.
""",
            author="amm,dev195",
            bpf="tcp",
            output=AlertOutput(label=__name__),
            optiondict={
                "ports": {
                    'help': 'comma-separated list of ports to watch for control connections (default: 21)',
                    'metavar': 'PORT,PORT,PORT,[...]',
                    'default': '21'},
                "dump": {
                    'action': 'store_true',
                    'help': 'dump files from stream'},
                "outdir": {
                    'help': 'directory to write output files (default: "ftpout")',
                    'metavar': 'DIRECTORY',
                    'default': 'ftpout'}
            }
        )

    def __update_bpf(self):
        """
        Dynamically change the BPF to allow processing of data transfer
        channels.
        """
        dynfilters = []
        for conn, metadata in self.conns.items():
            try:
                dynfilters += ["(host %s and host %s)" % metadata["tempippair"]]
            except (KeyError, TypeError):
                continue
        for a, p in self.data_channel_map.keys():
            dynfilters += ["(host %s and port %d)" % (a, p)]
        self.bpf = "(%s) and ((%s)%s)" % (
            self.original_bpf,
            " or ".join( "port %d" % p for p in self.control_ports ),
            " or " + " or ".join(dynfilters) if dynfilters else ""
        )
        self.recompile_bpf()

    def premodule(self):
        # dictionary containing metadata for connections
        self.conns = {}
        # dictionary mapping data channels (host, port) to their control channels
        self.data_channel_map = {}
        # ports used for control channels
        self.control_ports = set()
        # Original BPF without manipulation
        self.original_bpf = self.bpf
        # set control ports using user-provided info
        for p in self.ports.split(','):
            try:
                self.control_ports.add(int(p))
            except ValueError as e:
                self.error("{!r} is not a valid port. Skipping.".format(p))
        if not self.control_ports:
            self.error("Could not find any control ports. At least one must be set for this plugin.")
            sys.exit(1)

        # create output directory
        # break if it cannot be created
        if self.dump and not os.path.exists(self.outdir):
            try:
                os.makedirs(self.outdir)
            except (IOError, OSError) as e:
                self.error("Could not create output directory: {!r}: {!s}"
                           .format(self.outdir, e))
                sys.exit(1)

    def connection_init_handler(self, conn):
        # Create metadata containers for any new connections
        if conn.serverport in self.control_ports:
            self.conns[conn.addr] = {
                'mode': CTRL_CONN,
                'user': '',
                'pass': '',
                'path': [],
                'datachan': None,
                'lastcommand': '',
                'tempippair': None,
                'filedata': None,
                'file': ['', '', '']
            }
        elif self.dump and (conn.clientip, conn.clientport) in self.data_channel_map:
            self.conns[conn.addr] = {
                'mode': DATA_CONN,
                'ctrlchan': self.data_channel_map[(conn.clientip, conn.clientport)],
                'filedata': None
            }
        elif self.dump and (conn.serverip, conn.serverport) in self.data_channel_map:
            self.conns[conn.addr] = {
                'mode': DATA_CONN,
                'ctrlchan': self.data_channel_map[(conn.serverip, conn.serverport)],
                'filedata': None
            }
        elif self.dump:
            # This is a data connection with an unknown control connection. It
            # may be a passive mode transfer without known port info, yet.
            self.conns[conn.addr] = {
                'mode': DATA_CONN,
                'ctrlchan': None,
                'filedata': None
            }

    def connection_close_handler(self, conn):
        # After data channel closes, store file content in control channel's
        # 'filedata' field.
        # Control channel will write it to disk after it determines the
        # filename.
        try:
            info = self.conns[conn.addr]
        except KeyError:
            return

        if self.dump and info['mode'] == DATA_CONN:
            # find the associated control channel
            if info['ctrlchan'] == None:
                if (conn.clientip, conn.clientport) in self.data_channel_map:
                    info['ctrlchan'] = self.data_channel_map[(conn.clientip, conn.clientport)]
                if (conn.serverip, conn.serverport) in self.data_channel_map:
                    info['ctrlchan'] = self.data_channel_map[(conn.serverip, conn.serverport)]
            try:
                ctrlchan = self.conns[info['ctrlchan']]
            except KeyError:
                return
            # add data to control channel dictionary
            for blob in conn.blobs:
                if ctrlchan['filedata']:
                    ctrlchan['filedata'] += blob.data
                else:
                    ctrlchan['filedata'] = blob.data
            # update port list and data channel knowledge
            if (conn.serverip, conn.serverport) == ctrlchan['datachan']:
                del self.data_channel_map[ctrlchan['datachan']]
                ctrlchan['datachan'] = None
                self.__update_bpf()
            if (conn.clientip, conn.clientport) == ctrlchan['datachan']:
                del self.data_channel_map[ctrlchan['datachan']]
                ctrlchan['datachan'] = None
                self.__update_bpf()
            del self.conns[conn.addr]

        elif info['mode'] == CTRL_CONN:
            # clear control channels if they've been alerted on
            if info['file'] == None:
                del self.conns[conn.addr]

    def postmodule(self):
        for addr, info in self.conns.items():
            if self.dump and 'filedata' in info and info['filedata']:
                origname = info['file'][0] + '_' + os.path.join(*info['file'][1:3])
                outname = dshell.util.gen_local_filename(self.outdir, origname)
                with open(outname, 'wb') as fh:
                    fh.write(info['filedata'])
                numbytes = len(info['filedata'])
                info['filedata'] = None
                info['outfile'] = outname
                msg = 'User: %s, Pass: %s, %s File: %s (Incomplete: %d bytes written to %s)' % (info['user'], info['pass'], info['file'][0], os.path.join(*info['file'][1:3]), numbytes, os.path.basename(outname))
                self.write(msg, **info)


    def blob_handler(self, conn, blob):
        try:
            info = self.conns[conn.addr]
        except KeyError:
            # connection was not initialized correctly
            # set the blob to hidden and move on
            blob.hidden = True
            return

        if info['mode'] == DATA_CONN:
            return conn, blob

        try:
            data = blob.data
            data = data.decode('ascii')
        except UnicodeDecodeError as e:
            # Could not convert command data to readable ASCII
            blob.hidden = True
            return

        if blob.direction == 'cs':
            # client-to-server: try and get the command issued
            if ' ' not in data.rstrip():
                command = data.rstrip()
                param = ''
            else:
                command, param = data.rstrip().split(' ', 1)
            command = command.upper()
            info['lastcommand'] = command

            if command == 'USER':
                info['user'] = param

            elif command == 'PASS':
                info['pass'] = param

            elif command == 'CWD':
                info['path'].append(param)

            elif command == 'PASV' or command == 'EPSV':
                if self.dump:
                    # Temporarily store the pair of IP addresses
                    # to open up the BPF filter until blob_handler processes
                    # the response with the full IP/Port information.
                    # Note: Due to the way blob processing works, we don't
                    # get this information until after the data channel is
                    # established.
                    info['tempippair'] = tuple(
                        sorted((conn.clientip, conn.serverip))
                    )
                    self.__update_bpf()

            # For file transfers (including LIST), store tuple
            # (Direction, Path, Filename) in info['file']
            elif command == 'LIST':
                if param == '':
                    info['file'] = (
                        'RETR', os.path.normpath(os.path.join(*info['path']))
                        if len(info['path'])
                        else '', 'LIST'
                    )
                else:
                    info['file'] = (
                        'RETR', os.path.normpath(os.path.join(os.path.join(*info['path']), param))
                        if len(info['path'])
                        else '', 'LIST'
                    )
            elif command == 'RETR':
                info['file'] = (
                    'RETR', os.path.normpath(os.path.join(*info['path']))
                    if len(info['path'])
                    else '', param
                )
            elif command == 'STOR':
                info['file'] = (
                    'STOR', os.path.normpath(os.path.join(*info['path']))
                    if len(info['path'])
                    else '', param
                )

        # Responses
        else:
            # Rollback directory change unless 2xx response
            if info['lastcommand'] == 'CWD' and data[0] != '2':
                info['path'].pop()
            # Write out files upon resonse to transfer commands
            if info['lastcommand'] in ('LIST', 'RETR', 'STOR'):
                if self.dump and info['filedata']:
                    origname = info['file'][0] + '_' + os.path.join(*info['file'][1:3])
                    outname = dshell.util.gen_local_filename(self.outdir, origname)
                    with open(outname, 'wb') as fh:
                        fh.write(info['filedata'])
                    numbytes = len(info['filedata'])
                    info['filedata'] = None
                    info['outfile'] = outname
                    info.update(conn.info())
                    msg = 'User: "{}", Pass: "{}", {} File: {} ({:,} bytes written to {})'.format(
                        info['user'],
                        info['pass'],
                        info['file'][0],
                        os.path.join(*info['file'][1:3]),
                        numbytes,
                        os.path.basename(outname)
                    )
                else:
                    info.update(conn.info())
                    msg = 'User: "{}", Pass: "{}", {} File: {}'.format(
                        info['user'],
                        info['pass'],
                        info['file'][0],
                        os.path.join(*info['file'][1:3])
                    )
                    if data[0] not in ('1','2'):
                        msg += ' ({})'.format(data.rstrip())
                info['ts'] = blob.ts
                if (blob.sip == conn.sip):
                    self.write(msg, **info, dir_arrow="->")
                else:
                    self.write(msg, **info, dir_arrow="<-")
                info['file'] = None

            # Handle EPSV mode port setting
            if info['lastcommand'] == 'EPSV' and data[0] == '2':
                ret = re.findall('\(\|\|\|\d+\|\)', data)
                # TODO delimiters other than pipes
                if ret:
                    tport = int(ret[0].split('|')[3])
                    info['datachan'] = (conn.serverip, tport)
                    if self.dump:
                        self.data_channel_map[(conn.serverip, tport)] = conn.addr
                        info['tempippair'] = None
                        self.__update_bpf()

        # Look for ip/port information, assuming PSV response
        ret = re.findall('\d+,\d+,\d+,\d+,\d+\,\d+', data)
        if len(ret) == 1:
            tip, tport = self.calculateTransfer(ret[0])    # transfer ip, transfer port
            info['datachan'] = (tip, tport)                 # Update this control channel's knowledge of currently working data channel
            if self.dump:
                self.data_channel_map[(tip,tport)] = conn.addr     # Update plugin's global datachan knowledge
                info['tempippair'] = None
                self.__update_bpf()

        return conn, blob


    def calculateTransfer(self, val):
        # calculate passive FTP data port
        tmp = val.split(',')
        ip = '.'.join(tmp[:4])
        port = int(tmp[4])*256 + int(tmp[5])
        return ip, port


if __name__ == "__main__":
    print(DshellPlugin())
