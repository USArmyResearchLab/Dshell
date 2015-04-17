"""
2015 Feb 13

Goes through SMB traffic and snips out any file uploads it sees.

Specifically, it looks for create, write, and close commands and creates a
local file, writes the raw data to the local file, and closes the file,
respectively.
"""

import dshell
from smbdecoder import SMBDecoder
import sys
import util
import os

SMB_STATUS_SUCCESS = 0x0
SMB_COM_OPEN = 0x02		# Open a file.
SMB_COM_CLOSE = 0x04		# Close a file.
SMB_COM_NT_CREATE_ANDX = 0xa2  # Create or open a file or a directory.
SMB_COM_WRITE_ANDX = 0x2f		# Extended file write with AndX chaining.


class DshellDecoder(SMBDecoder):

    def __init__(self):
        self.fidhandles = {}  # dictionary to map fid handles to filenames
        # dictionary to map fid handles to local filedescriptors 
        # (ie. fd = open(fname,'wb'))
        self.fds = {}
        self.outdir = None 
        SMBDecoder.__init__(self,
                            name='rip-smb-uploads',
                            description='Extract files uploaded via SMB',
                            filter='tcp and port 445',
                            filterfn=lambda t: t[0][1] == 445 or t[1][1] == 445,
                            author='bg',
                            optiondict={
                                "outdir": {"help": "Directory to place files (default: ./smb_out)", "default": "./smb_out", "metavar": "DIRECTORY"},
                            }
                           )
        self.legacy = True

    def preModule(self):
        if not os.path.exists(self.outdir):
            try:
                os.makedirs(self.outdir)
            except OSError as e:
                self.error("Could not create directory '%s'\n%s" % (self.outdir, e))
                sys.exit(1)

    def SMBHandler(self, conn, request=None, response=None, requesttime=None, responsetime=None, cmd=None, status=None):
        # we only care about valid responses and matching request/response user
        # IDs
        if status == SMB_STATUS_SUCCESS and request.uid == response.uid:

            if cmd == SMB_COM_NT_CREATE_ANDX:  # file is being requested/opened
                self.debug('%s UID: %s  MID: %s  NT Create AndX  Status: %s' % (
                    conn.addr, request.uid, response.mid, hex(status)))
                filename = request.PARSE_NT_CREATE_ANDX_REQUEST(
                    request.smbdata)
                if type(filename) == type(None):
                    self.debug('Error: smb.SMB.PARSE_NT_CREATE_ANDX_REQUEST\n%s' % util.hexPlusAscii(request.smbdata))
                    return

                fid = response.PARSE_NT_CREATE_ANDX_RESPONSE(response.smbdata)
                self.debug('%s FID: %s' % (conn.addr, fid))

                if fid == -1:
                    self.debug('Error: smb.SMB.PARSE_NT_CREATE_ANDX_RESPONSE\n%s' % util.hexPlusAscii(response.smbdata))
                    self.debug(util.hexPlusAscii(response.smbdata))
                    return
                self.fidhandles[fid] = self.__localfilename(self.outdir, os.path.normpath(filename))

            elif cmd == SMB_COM_WRITE_ANDX:  # write data to the file
                fid, rawbytes = request.PARSE_WRITE_ANDX(request.smbdata)

                # do we have a local fd already open to handle this write?
                if fid in self.fds.keys():
                    self.fds[fid].write(rawbytes)
                else:
                    try:
                        fidhandle = self.fidhandles[fid]
                        self.fds[fid] = open(fidhandle, 'wb')
                        self.fds[fid].write(rawbytes)
                    except KeyError:
                        self.debug("Error: Could not find fidhandle for FID %s" % (fid))
                        return

            elif cmd == SMB_COM_CLOSE:  # file is being closed
                fid = request.PARSE_COM_CLOSE(request.smbdata)
                if fid in self.fds.keys():
                    self.log(repr(conn) + '\t%s' % (self.fidhandles[fid]))
                    self.fds[fid].close()
                    del self.fds[fid]
                if fid in self.fidhandles.keys():
                    self.debug('Closing FID: %s  Filename: %s' %
                               (hex(fid), self.fidhandles[fid]))
                    del self.fidhandles[fid]


    def __localfilename(self, path, origname):
        # Generates a local file name based on the original
        tmp = origname.replace("\\", "_")
        tmp = tmp.replace("/", "_")
        tmp = tmp.replace(":", "_")
        localname = ''
        for c in tmp:
            if ord(c) > 32 and ord(c) < 127:
                localname += c
            else:
                localname += "%%%02X" % ord(c)
        localname = os.path.join(path, localname)
        postfix = ''
        i = 0
        while os.path.exists(localname + postfix):
            i += 1
            postfix = "_%02d" % i
        return localname + postfix


if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
