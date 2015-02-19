##############################################
# File Transfer Protocol (FTP)
#
# Goes through TCP connections and tries to find FTP control channels and
# associated data channels. Optionally, it will write out any file data it
# sees into a separate directory.
#
# More specifically, it sets up an initial BPF that looks for control channels.
# As it finds them, it updates the BPF to include the data connection along
# ephemeral ports.
#
# If a data connection is seen, it prints a message indicating the user, pass,
# and file requested. If the dump flag is set, it also dumps the file into the
# __OUTDIR directory.
##############################################

import dshell
import os
import re

class DshellDecoder(dshell.TCPDecoder):

    def __init__(self):
        dshell.TCPDecoder.__init__(self,
                name='ftp',
                description='ftp',
                filter="tcp",
                author='amm',
                optiondict={
                    'port':{'type':'string',
                            'default':'21',
                            'help':'Port (or ports) to watch for control connections (Default: 21)'},
                    'dump':{'action':'store_true','help':'Dump files (Default: Off)'}
                }
                )

    # Constants for channel type
    __CTRLCONN = 0
    __DATACONN = 1
    __OUTDIR = 'ftpout'

    # Dynamically change the BPF filter
    # to allow processing of data transfer channels
    def __updatebpf(self):
        dynfilters =       [ '(host %s and host %s)' % self.conns[x]['tempippair'] for x in self.conns.keys() if 'tempippair' in self.conns[x] and self.conns[x]['tempippair'] != None ]
        dynfilters.extend( [ '(host %s and port %d)' % (a,p) for a,p in self.datachan.keys() ] )
        self.filter = 'tcp and (%s%s)' % (
                        ' or '.join(['port %d'%p for p in self.ctrlports]),
                        ' or '+' or '.join(dynfilters) if len(dynfilters) else ''
                )
        self.debug("Setting BPF filter to: %s" % self.filter)
        if 'capture' in dir(self):
            self.capture.setfilter(self.filter,1)

    def preModule(self):
        # Convert port specification from string to list of integers
        self.ctrlports = [int(p) for p in self.port.split(',')]
        self.datachan = {}   # Dictionary of control channels indexed by data channel (host, port) tuples
        self.conns = {}      # Dictionary of information about connections
        self.__updatebpf()       # Set initial bpf

        # Attempt to create output directory
        if self.dump:
            self.__OUTDIR = self.__mkoutdir(self.__OUTDIR)
            self.warn("Using output directory: %s" % self.__OUTDIR)

    def connectionInitHandler(self, conn):
        #
        # Setup conn info for New Data Channel
        #
        if conn.serverport in self.ctrlports:
            self.conns[conn.addr] = { 'mode': self.__CTRLCONN, 'user':'', 'pass':'', 'path':[], 'lastcommand':'', 'filedata':None, 'file':('', '', '')}
        elif self.dump and (conn.clientip, conn.clientport) in self.datachan:
            self.conns[conn.addr] = { 'mode': self.__DATACONN, 'ctrlchan': self.datachan[(conn.clientip, conn.clientport)] }
        elif self.dump and (conn.serverip, conn.serverport) in self.datachan:
            self.conns[conn.addr] = { 'mode': self.__DATACONN, 'ctrlchan': self.datachan[(conn.serverip, conn.serverport)] }
        elif self.dump:
            # No match.  Track as a DATACONN with unknown CTRLCHAN as it may be
            #            a passive mode transfer that we don't have port info on yet.
            self.conns[conn.addr] = { 'mode': self.__DATACONN, 'ctrlchan': None }

    def connectionCloseHandler(self, conn):
        info = self.conns[conn.addr]
        #########################################################
        # Upon close of data channels, store file content in
        # 'filedata' associated with the ctrlchan.
        # ctrlchan will then write it out to disk after it knows
        # for sure the file name
        #
        if self.dump and info['mode'] == self.__DATACONN:
            # Associated Control Channel
            if info['ctrlchan'] == None:
                if (conn.clientip, conn.clientport) in self.datachan:
                    info['ctrlchan'] = self.datachan[(conn.clientip, conn.clientport)]
                if (conn.serverip, conn.serverport) in self.datachan:
                    info['ctrlchan'] = self.datachan[(conn.serverip, conn.serverport)]
            ctrlchan = self.conns[info['ctrlchan']]
            # Add data to control channel
            ctrlchan['filedata'] = conn.data()
            # Update BPF and DataChan Knowledge
            if (conn.serverip, conn.serverport) == ctrlchan['datachan'] or (conn.clientip, conn.clientport) == ctrlchan['datachan']:
                del self.datachan[ctrlchan['datachan']]
                ctrlchan['datachan'] = None
                self.__updatebpf()
            # Remove Data Channel from tracker
            del self.conns[conn.addr]

        elif info['mode'] == self.__CTRLCONN:
            if 'file' not in info or info['file'] == None:
                del self.conns[conn.addr]

    def postModule(self):
        for x in self.conns:
            info = self.conns[x]
            if self.dump and 'filedata' in info and info['filedata']:
                origname = info['file'][0] + '_' + os.path.join(*info['file'][1:3])
                outname = self.__localfilename(self.__OUTDIR, origname)
                fh = open(outname, 'w')
                fh.write(info['filedata'])
                fh.close()
                numbytes = len(info['filedata'])
                info['filedata'] = None
                info['outfile'] = outname
                #info.update(conn.info())
                msg = 'User: %s, Pass: %s, %s File: %s (Incomplete: %d bytes written to %s)' % (info['user'], info['pass'], info['file'][0], os.path.join(*info['file'][1:3]), numbytes, os.path.basename(outname))
                self.alert(msg, **info)



    def blobHandler(self, conn, blob):

        info = self.conns[conn.addr]
        data = blob.data()

        #
        # Data Channel
        #
        if info['mode'] == self.__DATACONN:
            return


        #
        # Control Channel
        #

        # Client Commands
        if blob.direction == 'cs':

            try:
                if ' ' not in data: (command, param) = (data.rstrip(), '')
                else: (command, param) = data.rstrip().split(' ', 1)
                command = command.upper()
                info['lastcommand'] = command
            except:
                return

            if command == 'USER':
                info['user'] = param
            elif command == 'PASS':
                info['pass'] = param
            elif command == 'CWD':
                info['path'].append(param)
            elif command == 'PASV' or command == 'EPSV':
                if self.dump:
                    # Temporarily store the pair of IP addresses
                    # to open up the bpf filter until blobHandler processes
                    # the response with the full IP/Port information
                    # (Note: Due to the way blob processing works, we don't get this information
                    #        until after the data channel is established)
                    info['tempippair'] = tuple(sorted((conn.clientip, conn.serverip)))
                    self.__updatebpf()
            #
            # For file transfers (including LIST), store tuple (Direction, Path, Filename) in info['file']
            #
            elif command == 'LIST':
                if param == '':
                    info['file'] = ( 'RETR', os.path.normpath(os.path.join(*info['path'])) if len(info['path']) else '', 'LIST' )
                else:
                    info['file'] = ( 'RETR', os.path.normpath(os.path.join(os.path.join(*info['path']), param)) if len(info['path']) else '', 'LIST' )
            elif command == 'RETR':
                info['file'] = ( 'RETR', os.path.normpath(os.path.join(*info['path'])) if len(info['path']) else '', param )
            elif command == 'STOR':
                info['file'] = ( 'STOR', os.path.normpath(os.path.join(*info['path'])) if len(info['path']) else '', param )

        # Responses
        else:
            #
            # Rollback directory change unless 2xx response
            #
            if info['lastcommand'] == 'CWD' and data[0] != '2': info['path'].pop()
            #
            # Write out files upon resonse to transfer commands
            #
            if info['lastcommand'] in ('LIST', 'RETR', 'STOR'):
                if self.dump and info['filedata']:
                    origname = info['file'][0] + '_' + os.path.join(*info['file'][1:3])
                    outname = self.__localfilename(self.__OUTDIR, origname)
                    fh = open(outname, 'w')
                    fh.write(info['filedata'])
                    fh.close()
                    numbytes = len(info['filedata'])
                    info['filedata'] = None
                    info['outfile'] = outname
                    info.update(conn.info())
                    msg = 'User: %s, Pass: %s, %s File: %s (%d bytes written to %s)' % (info['user'], info['pass'], info['file'][0], os.path.join(*info['file'][1:3]), numbytes, os.path.basename(outname))
                else:
                    info.update(conn.info())
                    msg = 'User: %s, Pass: %s, %s File: %s' % (info['user'], info['pass'], info['file'][0], os.path.join(*info['file'][1:3]))
                    if data[0] not in ('1','2'): msg += ' (%s)' % data.rstrip()
                self.alert(msg, **info)
                info['file'] = None
            #
            # Handle EPSV mode port setting
            #
            if info['lastcommand'] == 'EPSV' and data[0] == '2':
                ret = re.findall('\(\|\|\|\d+\|\)', data)
                if ret:
                    tport = int(ret[0].split('|')[3])
                    info['datachan'] = (conn.serverip, tport)
                    if self.dump:
                        self.datachan[(conn.serverip, tport)] = conn.addr
                        info['tempippair'] = None
                        self.__updatebpf()

        #
        # Look for ip/port information, assuming PSV response
        #
        ret = re.findall('\d+,\d+,\d+,\d+,\d+\,\d+', data)
        if len(ret)==1:
            tip, tport = self.calculateTransfer(ret[0])    # transfer ip, transfer port
            info['datachan'] = (tip, tport)                 # Update this control channel's knowledge of currently working data channel
            if self.dump:
                self.datachan[(tip,tport)] = conn.addr     # Update decoder's global datachan knowledge
                info['tempippair'] = None
                self.__updatebpf()


    def calculateTransfer(self,val):
        # calculate passive FTP data port
        tmp = val.split(',')
        ip = '.'.join(tmp[:4])
        port = int(tmp[4])*256 + int(tmp[5])
        return ip, port

    #
    # Create output directory.  Returns full path to output directory.
    #
    def __mkoutdir(self, outdir):
        path = os.path.realpath(outdir)
        if os.path.exists(path): return path
        try:
            os.mkdir(path)
            return path
        except OSError:
            pass   # most likely a permission denied issue, continue and try system temp directory
        except:
            raise  # other errors, abort
        if os.path.exists('/tmp'): path = os.path.realpath(os.path.join('/tmp', outdir))
        if os.path.exists(path): return path
        try:
            os.mkdir(path)
            return path
        except:
            raise

    #
    # Generate a local (extracted) filename based on the original
    #
    def __localfilename(self, path, origname):
        tmp = origname.replace("\\", "_")
        tmp = tmp.replace("/", "_")
        tmp = tmp.replace(":", "_")
        localname = ''
        for c in tmp:
            if ord(c) > 32 and ord(c) < 127:
                localname += c
            else:
                localname += "%%%02X" % ord(c)
        localname = path + '/' + localname
        postfix = ''
        i = 0
        while os.path.exists(localname+postfix):
            i += 1
            postfix = "_%02d" % i
        return localname+postfix

if __name__=='__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
