"""
2015 Feb 13

Processes SMB traffic and attempts to extract command/response information
from psexec.

When a successful SMB connection is seen and it matches a psexec regular
expression, it creates a new "psexec" object to store connection information
and messages.

Once the connection closes, an alert is generated (of configurable verbosity)
relaying basic information and messages passed.
"""

#import dshell
from smbdecoder import SMBDecoder
import colorout
import util
import re
import datetime

SMB_STATUS_SUCCESS = 0x0
SMB_COM_OPEN = 0x02		# Open a file.
SMB_COM_CLOSE = 0x04		# Close a file.
SMB_COM_NT_CREATE_ANDX = 0xa2  # Create or open a file or a directory.
SMB_COM_WRITE_ANDX = 0x2f		# Extended file write with AndX chaining.
SMB_COM_READ_ANDX = 0x2E
SMB_COM_SESSION_SETUP_ANDX = 0x73


class DshellDecoder(SMBDecoder):

    def __init__(self):
        # dictionary indexed by uid, points to login domain\name (string)
        self.uidname = {}
        self.fidhandles = {}  # dictionary to map fid handles to psexec objects
        # dictionary of psexec objects, indexed by conn+PID (use sessIndex
        # function)
        self.psexecobjs = {}
        # FID won't work as an index because each stream has its own
        SMBDecoder.__init__(self,
                            name='psexec',
                            description='Extract command/response information from psexec over smb',
                            filter='tcp and (port 445 or port 139)',
                            filterfn=lambda t: t[0][1] == 445 or t[1][1] == 445 or t[0][1] == 139 or t[1][1] == 139,
                            author='amm',
                            optiondict={
                                'alertsonly': {'action': 'store_true', 'help': 'only dump alerts, not content'},
                                'htmlalert': {'action': 'store_true', 'help': 'include html as named value in alerts'},
                                'time': {'action': 'store_true', 'help': 'display command/response timestamps'}
                            }
                           )
        self.legacy = True
        # self.out=colorout.ColorOutput(title='psexec')
        self.output = 'colorout'

    def sessIndexFromPID(self, conn, pid):
        return ':'.join((str(conn.starttime), conn.sip, str(conn.sport), conn.dip, str(conn.dport), pid))

    def connectionHandler(self, conn):
        SMBDecoder.connectionHandler(self, conn)
        for k in self.psexecobjs.keys():
            del self.psexecobjs[k]

    #
    # Internal class to contain psexec session information
    #
    class psexec:

        def __init__(self, parent, conn, hostname, pid, opentime):
            self.parent = parent
            self.conn = conn
            self.hostname = hostname
            self.pid = pid
            self.opentime = opentime
            self.closetime = conn.endtime
            self.username = ''
            self.open_iohandles = {}  # indexed by FID, points to filename
            self.closed_iohandles = {}
            self.msgList = []  # List of tuples (text, direction)
            self.csCount = 0
            self.scCount = 0
            self.csBytes = 0
            self.scBytes = 0
            self.lastDirection = ''

        def addmsg(self, text, direction, ts):
            # Only store timestamp information if this is a change in direction
            if direction == self.lastDirection:
                self.msgList.append((text, direction, None))
            else:
                self.msgList.append((text, direction, ts))
                self.lastDirection = direction
            if direction == 'cs':
                self.csCount += 1
                self.csBytes += len(text)
            elif direction == 'sc':
                self.scCount += 1
                self.scBytes += len(text)

        def addIO(self, fid, name):
            if fid in self.open_iohandles:
                self.parent.warn("IO Handle with FID %s (%s) is already associated with psexec session %d" % (
                    hex(fid), name, self.pid))
            self.open_iohandles[fid] = name

        def delIO(self, fid):
            if fid in self.open_iohandles:
                self.closed_iohandles[fid] = self.open_iohandles[fid]
                del self.open_iohandles[fid]

        def handleCount(self):
            return len(self.open_iohandles)
        #
        # Long output (screen/html)
        #

        def write(self, out=None):
            if out == None:
                out = self.parent.out
            out.write("PSEXEC Service from host %s with PID %s\n" %
                      (self.hostname, self.pid), formatTag='H1')
            if len(self.username):
                out.write("User: %s\n" % (self.username), formatTag='H2')
            out.write("Start: %s UTC\n  End: %s UTC\n" % (datetime.datetime.utcfromtimestamp(
                self.conn.starttime), datetime.datetime.utcfromtimestamp(self.conn.endtime)), formatTag='H2')
            out.write("%s:%s -> %s:%s\n" % (self.conn.clientip, self.conn.clientport,
                                            self.conn.serverip, self.conn.serverport), formatTag="H2", direction="cs")
            out.write("%s:%s -> %s:%s\n\n" % (self.conn.serverip, self.conn.serverport,
                                              self.conn.clientip, self.conn.clientport), formatTag="H2", direction="sc")
            for msg in self.msgList:
                out.write(
                    msg[0], direction=msg[1], timestamp=msg[2], time=self.parent.time)
            out.write("\n")
        #
        # Short output (alert)
        #

        def alert(self):
            kwargs = {'hostname': self.hostname, 'pid': self.pid, 'username': self.username,
                      'opentime': self.opentime, 'closetime': self.closetime,
                      'csCount': self.csCount, 'scCount': self.scCount, 'csBytes': self.csBytes, 'scBytes': self.scBytes}
            if self.parent.htmlalert:
                htmlfactory = colorout.ColorOutput(
                    htmlgenerator=True, title="psexec")
                self.write(htmlfactory)
                htmlfactory.close()
                kwargs['html'] = htmlfactory.htmldump()
            kwargs.update(self.conn.info())
            kwargs['ts'] = self.opentime
            self.parent.alert(
                "Host: %s, PID: %s, CS: %d, SC: %d, User: %s" % (
                    self.hostname, self.pid, self.csBytes, self.scBytes, self.username),
                kwargs
            )

        def __del__(self):
            if self.parent.alertsonly:
                self.alert()
            else:
                self.write()

    def SMBHandler(self, conn, request=None, response=None, requesttime=None, responsetime=None, cmd=None, status=None):
        # we only care about valid responses and matching request/response user
        # IDs
        if status == SMB_STATUS_SUCCESS and request.uid == response.uid:

            if cmd == SMB_COM_SESSION_SETUP_ANDX and type(status) != type(None):
                auth_record = request.PARSE_SESSION_SETUP_ANDX_REQUEST(
                    request.smbdata)
                if not(auth_record):
                    return
                domain_name = auth_record.domain_name
                user_name = auth_record.user_name
                self.uidname[response.uid] = "%s\\%s" % (
                    domain_name, user_name)

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
                match = re.search(
                    r'psexecsvc-(.*)-(\d+)-(stdin|stdout|stderr)', filename)
                if not match:
                    return

                # We have a PSEXEC File Handle!
                hostname = match.group(1)
                pid = match.group(2)
                iohandleName = match.group(3)
                sessionIndex = self.sessIndexFromPID(conn, pid)
                if not sessionIndex in self.psexecobjs:
                    self.psexecobjs[sessionIndex] = self.psexec(
                        self, conn, hostname, pid, requesttime)
                self.fidhandles[fid] = self.psexecobjs[sessionIndex]
                self.fidhandles[fid].addIO(fid, filename)
                if response.uid in self.uidname:
                    self.fidhandles[fid].username = self.uidname[response.uid]

            elif cmd == SMB_COM_WRITE_ANDX:  # write data to the file
                fid, rawbytes = request.PARSE_WRITE_ANDX(request.smbdata)
                self.debug('COM_WRITE_ANDX\n%s' %
                           (util.hexPlusAscii(request.smbdata)))
                if fid in self.fidhandles:
                    self.fidhandles[fid].addmsg(rawbytes, 'cs', requesttime)

            elif cmd == SMB_COM_READ_ANDX:  # write data to the file
                fid = request.PARSE_READ_ANDX_Request(request.smbdata)
                rawbytes = response.PARSE_READ_ANDX_Response(response.smbdata)
                self.debug('COM_READ_ANDX (FID %s)\n%s' %
                           (fid, util.hexPlusAscii(response.smbdata)))
                if fid in self.fidhandles:
                    self.fidhandles[fid].addmsg(rawbytes, 'sc', responsetime)

            elif cmd == SMB_COM_CLOSE:  # file is being closed
                fid = request.PARSE_COM_CLOSE(request.smbdata)
                if fid in self.fidhandles.keys():
                    self.fidhandles[fid].delIO(fid)
                    self.debug('Closing FID: %s  Filename: %s' %
                               (hex(fid), self.fidhandles[fid]))
                    if self.fidhandles[fid].handleCount() < 1 and self.sessIndexFromPID(conn, self.fidhandles[fid].pid) in self.psexecobjs:
                        self.psexecobjs[
                            self.sessIndexFromPID(conn, self.fidhandles[fid].pid)].closetime = responsetime
                        del self.psexecobjs[
                            self.sessIndexFromPID(conn, self.fidhandles[fid].pid)]
                    del self.fidhandles[fid]


if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
