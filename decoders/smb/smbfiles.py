"""
2015 Feb 13

Processes SMB traffic and tries to find file reads and writes.

When a read or write action is seen, the size of the transfer is recorded in
a new "smbfile" object and a count is incremented for the type of action taken
(i.e. reads+1 or writes+1).

After the connection closes, an alert is generated showing some information
about the connection, the action taken (read, write, or both), the full name
of the file and how much data was transferred.
"""

from smbdecoder import SMBDecoder
import util

SMB_STATUS_SUCCESS = 0x0
SMB_COM_OPEN = 0x02		# Open a file.
SMB_COM_CLOSE = 0x04		# Close a file.
SMB_COM_NT_CREATE_ANDX = 0xa2  # Create or open a file or a directory.
SMB_COM_WRITE_ANDX = 0x2f		# Extended file write with AndX chaining.
SMB_COM_READ_ANDX = 0x2E
SMB_COM_SESSION_SETUP_ANDX = 0x73
SMB_COM_TREE_CONNECT_ANDX = 0x75


class DshellDecoder(SMBDecoder):

    def __init__(self):
        # dictionary indexed by uid, points to login tuple (hostname,
        # domain\name) (string)
        self.uidname = {}
        self.tidmap = {}     # dictionary indexed by tid, points to tree path
        # dictionary of smb file objects, indexed by conn+fid (use
        # sessIndexFromFID function)
        self.smbfileobjs = {}
        SMBDecoder.__init__(self,
                            name='smbfiles',
                            description='List files accessed via smb',
                            filter='tcp and (port 445 or port 139)',
                            filterfn=lambda t: t[0][1] == 445 or t[1][1] == 445 or t[0][1] == 139 or t[1][1] == 139,
                            author='amm',
                            optiondict={
                                'nopsexec': {'action': 'store_true', 'help': 'supress psexecsvc streams from output'},
                                'activeonly': {'action': 'store_true', 'help': 'only output files with reads or writes'}
                            }
                           )

    def fileIndexFromFID(self, conn, fid):
        return ':'.join((str(conn.starttime), conn.sip, str(conn.sport), conn.dip, str(conn.dport), str(fid)))

    def connectionHandler(self, conn):
        SMBDecoder.connectionHandler(self, conn)
        for k in self.smbfileobjs.keys():
            del self.smbfileobjs[k]

    #
    # Internal class to contain info about files
    #
    class smbfile:

        def __init__(self, parent, conn, fid, opentime, filename, username, hostname, treepath):
            self.parent = parent
            self.conn = conn
            self.opentime = opentime
            self.closetime = conn.endtime
            self.filename = filename
            self.username = username
            self.hostname = hostname
            self.treepath = treepath
            self.writes = 0
            self.reads = 0
            self.byteswritten = 0
            self.bytesread = 0

        def writeblock(self, data):
            self.writes += 1
            self.byteswritten += len(data)

        def readblock(self, data):
            self.reads += 1
            self.bytesread += len(data)

        def alert(self):
            if self.parent.nopsexec and self.filename.lower().startswith('\psexecsvc'):
                return
            if self.reads > 0 and self.writes > 0:
                mode = 'B'
            elif self.reads > 0:
                mode = 'R'
            elif self.writes > 0:
                mode = 'W'
            else:
                mode = '-'
            if self.parent.activeonly and mode == '-':
                return
            kwargs = {
                'filename': self.filename, 'username': self.username, 'hostname': self.hostname, 'treepath': self.treepath,
                'opentime': self.opentime, 'closetime': self.closetime, 'mode': mode,
                'writes': self.writes, 'reads': self.reads, 'byteswritten': self.byteswritten, 'bytesread': self.bytesread
            }
            kwargs.update(self.conn.info())
            kwargs['ts'] = self.opentime
            self.parent.alert(
                "%s %s%s (%s)" % (
                    self.username, self.treepath, self.filename, mode),
                kwargs
            )

        def __del__(self):
            self.alert()

    def SMBHandler(self, conn, request=None, response=None, requesttime=None, responsetime=None, cmd=None, status=None):
        # we only care about valid responses and matching request/response user
        # IDs
        if status == SMB_STATUS_SUCCESS and request.uid == response.uid:

            #
            # SMB_COM_SESSION_SETUP - Start tracking user authentication by UID
            #
            if cmd == SMB_COM_SESSION_SETUP_ANDX and type(status) != type(None):
                auth_record = request.PARSE_SESSION_SETUP_ANDX_REQUEST(
                    request.smbdata)
                if not(auth_record):
                    return
                domain_name = auth_record.domain_name
                user_name = auth_record.user_name
                host_name = auth_record.host_name
                self.uidname[response.uid] = (
                    host_name, "%s\%s" % (domain_name, user_name))

            #
            # SMB_COM_TREE_CONNECT - Start tracking tree by TID
            #
            if cmd == SMB_COM_TREE_CONNECT_ANDX:
                request_path = unicode(request.SMB_COM_TREE_CONNECT_ANDX_Request(
                    request.smbdata), 'utf-16').encode('utf-8').rstrip('\0')
                self.tidmap[response.tid] = request_path

            #
            # SMB_COM_NT_CREATE - Start tracking file handle by FID
            #
            # file is being requested/opened
            elif cmd == SMB_COM_NT_CREATE_ANDX:
                self.debug('%s UID: %s  MID: %s  NT Create AndX  Status: %s' % (
                    conn.addr, request.uid, response.mid, hex(status)))
                filename = request.PARSE_NT_CREATE_ANDX_REQUEST(
                    request.smbdata)
                if type(filename) == type(None):
                    self.debug('Error: smb.SMB.PARSE_NT_CREATE_ANDX_REQUEST\n%s' % util.hexPlusAscii(
                        request.smbdata))
                    return
                fid = response.PARSE_NT_CREATE_ANDX_RESPONSE(response.smbdata)
                if fid == -1:
                    self.debug('Error: smb.SMB.PARSE_NT_CREATE_ANDX_RESPONSE\n%s' % util.hexPlusAscii(
                        response.smbdata))
                    self.debug(util.hexPlusAscii(response.smbdata))
                    return
                # Setup smbfile object
                if response.uid in self.uidname:
                    hostname, username = self.uidname[response.uid]
                else:
                    hostname = 'Unknown'
                    username = 'Unknown\\Unknown'
                if response.tid in self.tidmap:
                    treepath = self.tidmap[response.tid]
                else:
                    treepath = ''
                fileobj = self.smbfile(
                    self, conn, fid, requesttime, filename, username, hostname, treepath)
                fileIndex = self.fileIndexFromFID(conn, fid)
                self.smbfileobjs[fileIndex] = fileobj

            #
            # SMB_COM_WRITE - File writes
            #
            elif cmd == SMB_COM_WRITE_ANDX:  # write data to the file
                fid, rawbytes = request.PARSE_WRITE_ANDX(request.smbdata)
                #self.debug('COM_WRITE_ANDX\n%s' % (util.hexPlusAscii(request.smbdata)))
                fileIndex = self.fileIndexFromFID(conn, fid)
                if fileIndex in self.smbfileobjs:
                    self.smbfileobjs[fileIndex].writeblock(rawbytes)

            #
            # SMB_COM_READ - File reads
            #
            elif cmd == SMB_COM_READ_ANDX:  # read data from the file
                fid = request.PARSE_READ_ANDX_Request(request.smbdata)
                rawbytes = response.PARSE_READ_ANDX_Response(response.smbdata)
                #self.debug('COM_READ_ANDX (FID %s)\n%s' % (fid, util.hexPlusAscii(response.smbdata)))
                fileIndex = self.fileIndexFromFID(conn, fid)
                if fileIndex in self.smbfileobjs:
                    self.smbfileobjs[fileIndex].readblock(rawbytes)

            #
            # SMB_COM_CLOSE - Closing file
            #
            elif cmd == SMB_COM_CLOSE:  # file is being closed
                fid = request.PARSE_COM_CLOSE(request.smbdata)
                fileIndex = self.fileIndexFromFID(conn, fid)
                if fileIndex in self.smbfileobjs:
                    self.smbfileobjs[fileIndex].closetime = responsetime
                    del self.smbfileobjs[fileIndex]

if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
