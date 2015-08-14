'''
2015 Feb 13

Extend dshell.TCPDecoder to handle SMB Message Requests/Responses

Will call SMBHandler(
            conn = Connection(),
            request=dshell.smb.smbdecoder.SMB(),
            response=dshell.smb.smbdecoder.SMB(),
            requesttime=timestamp,
            responsetime=timestamp,
            cmd= <type 'int'>  [3]
            status= <type 'int'>  [2]  A 32-bit field used to communicate error
                                       messages from the server to the client
            )

Requests are tracked by MID 

It will be up to the decoder to handle each SMB Command.

Several functions create throw-away variables when unpacking data. Because of
this, pylint checks were run with "-d unused-variables"

References:
[1] http://anonsvn.wireshark.org/viewvc/trunk/epan/dissectors/packet-smb.c?revision=32650&view=co&pathrev=32650
[2] http://msdn.microsoft.com/en-us/library/ee441774%28v=prot.13%29.aspx    SMB Header Protocol Definition
[3] http://msdn.microsoft.com/en-us/library/ee441616(v=prot.13).aspx
'''


import dshell
import struct
#import binascii

SMB_PROTOCOL = '\xffSMB'
SMB_STATUS_SUCCESS = 0x0
NTLMSSP_IDENT = 'NTLMSSP\x00'
NTLMSSP_AUTH = 0x00000003
NTLMSSP_CHALLENGE = 0x00000002


class SMBDecoder(dshell.TCPDecoder):

    def __init__(self, **kwargs):
        self.requests = {}  # requests are stored by MID
        dshell.TCPDecoder.__init__(self, **kwargs)

    def connectionInitHandler(self, conn):
        self.requests[conn.addr] = {}

    def blobHandler(self, conn, blob):
        data = blob.data()
        offset = 0
        datalen = len(data)
        while offset < datalen:
            try:
                offset += self.smbFactory(conn, blob, data[offset:])
            except InsufficientData:
                return

    # Returns number of bytes used by NetBIOS+SMB
    # e.g. mlength+4
    def smbFactory(self, conn, blob, data):

        try:
            msgtype, mlength, smbdata = self.parseNetBIOSSessionService(data)
        except InsufficientData:
            raise

        try:
            # create SMB Message (abstract data model: SMB header + extra)
            smb = SMB(smbdata)
        except InsufficientData:
            raise

        if smb.proto != SMB_PROTOCOL:
            return mlength + 4

        if blob.direction == 'cs':
            self.requests[conn.addr][smb.mid] = [blob.starttime, smb]
        elif blob.direction == 'sc':
            if smb.mid in self.requests[conn.addr].keys():
                requesttime, request = self.requests[conn.addr][smb.mid]
                responsetime, response = blob.starttime, smb

                if 'SMBHandler' in dir(self):
                    self.SMBHandler(conn=conn, request=request, response=response,
                                    requesttime=requesttime, responsetime=responsetime, cmd=smb.cmd, status=smb.status)

                del self.requests[conn.addr][smb.mid]

        return mlength + 4

    def connectionHandler(self, conn):
        """ clean up all requests associated with this connection """
        if conn.addr in self.requests:
            if len(self.requests[conn.addr]) > 0:
                for mid in self.requests[conn.addr].keys():
                    requesttime, request = self.requests[conn.addr][mid]
                    self.SMBHandler(conn=conn, request=request, response=None,
                                    requesttime=requesttime, responsetime=None, cmd=request.cmd, status=-1)
                    del self.requests[conn.addr][mid]
            del self.requests[conn.addr]

    def postModule(self):
        """ clean up self.requests to process all SMB messages that only have a single request and no response """
        for k in self.requests.keys():
            for mid in self.requests[k].keys():
                requesttime, request = self.requests[k][mid]
                self.SMBHandler(conn=None, request=request, response=None,
                                requesttime=requesttime, responsetime=None, cmd=request.cmd, status=-1)
                del self.requests[k][mid]
            del self.requests[k]

    def parseNetBIOSSessionService(self, data):
        """ parse the NetBIOS Session Service header [2]"""
        if len(data) < 4:
            raise InsufficientData
        msgtype = struct.unpack('B', data[0])[0]
        arg1, arg2, arg3 = struct.unpack('3B', data[1:4])
        mlength = (arg1 * 512) + (arg2 * 256) + arg3
        smbdata = data[4:]
        return msgtype, mlength, smbdata

    def SMBHandler(self, conn, request=None, response=None, requesttime=None, responsetime=None, cmd=None, status=None):
        "Placeholder. Overwrite in separate decoders."
        pass


class InsufficientData(Exception):
    pass


class SMB():

    def __init__(self, pktdata):
        """
        Generic SMB class.  Handles parsing of SMB Header Messages and some specific SMB Command Objects

        Reference:
        [1] http://msdn.microsoft.com/en-us/library/ee441774%28v=prot.13%29.aspx	SMB Header Protocol Definition
        [2] http://msdn.microsoft.com/en-us/library/ee441616(v=prot.13).aspx


        proto = 4 bytes		4s	4-byte literal string '\xFF', 'S', 'M', 'B'
        cmd = 1 byte		B	one-byte command code, commands listed at [2]
        status = 4 bytes	I	A 32-bit field used to communicate error messages from the server to the client [SUCCESS = 0x0000
        flags1 = 1 byte		B
        flags2 = 2 bytes	H
        pidhigh = 2 bytes	H
        security = 8 bytes	8s
        reserved = 2 bytes	H
        tid = 2 bytes		H
        pidlow = 2 bytes	H
        uid = 2 bytes		H	Associate a session with a specific user
        mid = 2 bytes		H	Multiplexer identifier
        """
        self.filename = None
        if len(pktdata) < 32:
            raise InsufficientData
        self.proto, self.cmd, self.status, self.flags1, self.flags2, self.pidhigh, self.security, self.reserved, self.tid, self.pidlow, self.uid, self.mid = struct.unpack(
            '<4sBIBHH8sHHHHH', pktdata[:32])
        self.smbdata = pktdata[32:]

    def PARSE_NT_CREATE_ANDX_REQUEST(self, data):
        """ return the filename associated with the request (return None if err)"""
        try:
            wct, andxcmd, rsrv1, andxoffset, rsrv2, filenamelen, cflags, rootfid, mask, size, attrib, share = struct.unpack(
                '<BBBHBHIIIQII', data[:36])
            disposition, createopts, impersonation, sflags, bytecount = struct.unpack(
                '<IIIBH', data[36:51])
            fmtstr = '<%ss' % (bytecount)
            filename = struct.unpack(fmtstr, data[51:])[0].replace(
                '\x00', '')  # hack for unicode to ascii
            self.filename = filename
            return filename
        except:
            return None

    def PARSE_NT_CREATE_ANDX_RESPONSE(self, data):
        """ return the FID associated with the requested filename """
        try:
            wct, andxcmd, rsrv1, andxoffset, oplock = struct.unpack(
                '<BBBHB', data[:6])
            fid, caction, created, lastaccess, lastwrite, change = struct.unpack(
                '<HIQQQQ', data[6:44])
            fattrib, size, eof, ftype, ipcstate, isdirectory, bytecount = struct.unpack(
                '<IQQHHBH', data[44:71])
            return fid
        except:
            return -1

    def PARSE_COM_CLOSE(self, data):
        """ return the FID associated with the CLOSE request """
        try:
            wct, fid, lastwrite, bytecount = struct.unpack('<BHIH', data[:9])
            return fid
        except:
            return -1

    def PARSE_WRITE_ANDX(self, data):
        """
        parse WRITE_ANDX message to extract the FID and raw bytes
        return fid (file handle to be written) and the raw bytes: return fid,rawbytes)
        -1 and '' if err
        """
        try:
            wct, andxcmd, rsrv1, andxoffset, fid, offset, rsrv2 = struct.unpack(
                '<BBBHHII', data[:15])
            writemode, remaining, datalenhigh, datalenlow, dataoffset = struct.unpack(
                '<HHHHH', data[15:25])
            highoffset, bytecount, padding = struct.unpack('<IHB', data[25:32])
            rawbytes = data[32:32 + datalenlow + datalenhigh * 65536]
            return fid, rawbytes
        except:
            return -1, ''

    def PARSE_READ_ANDX_Request(self, data):
        """
        parse READ_ANDX request message to extract the FID
        return fid (file handle to be written)
        -1 if err
        """
        try:
            fid = struct.unpack('<H', data[5:7])[0]
            return fid
        except:
            return -1

    def PARSE_READ_ANDX_Response(self, data):
        """
        parse READ_ANDX response message to extract the raw bytes
        return the raw bytes: return rawbytes
        '' if err
        """
        try:
            wct, andxcmd, rsrv1, andxoffset = struct.unpack('<BBBH', data[:5])
            remaining, datacompactmode, resv2 = struct.unpack(
                '<HHH', data[5:11])
            datalenlow, dataoffset, datalenhigh = struct.unpack(
                '<HHI', data[11:19])
            bytecount, padding = struct.unpack('<HB', data[25:28])
            return data[28:27 + bytecount]
        except:
            return ''

    def PARSE_SESSION_SETUP_ANDX_REQUEST(self, data):
        """ only currently supports NTLMSSP Authentication Requests/Responses """
        try:
            wct, andxcmd, rsrv1, andxoffset, maxbuf, maxmpxcount, vcnum = struct.unpack(
                '<BBBHHHH', data[:11])
            sessionkey, securitybloblen, rsrv2, capabilities, bytecount = struct.unpack(
                '<IHIIH', data[11:27])
            secblob = data[27:27 + securitybloblen]

            # Position of the NTLMSSP_IDENT byte sequence appears to be variable within the secblob,
            # depending on subtleties in the protocol stack that I haven't
            # researched.  But this seems to work...
            if NTLMSSP_IDENT in secblob:
                offset = secblob.find(NTLMSSP_IDENT)
                if offset > len(secblob):
                    return None
                msgtype = struct.unpack(
                    '<I', secblob[offset + 8:offset + 12])[0]
                if msgtype == NTLMSSP_AUTH:
                    auth_record = NTLMSSP_AUTH_RECORD(secblob[offset:])
                    if auth_record.valid:
                        return auth_record
                    else:
                        return None
                elif msgtype == NTLMSSP_CHALLENGE:
                    auth_record = NTLMSSP_CHALLENGE_RECORD(secblob[offset:])
                    if auth_record.valid:
                        return auth_record
                    else:
                        return None
            return None
        except:
            return None

    def SMB_COM_TREE_CONNECT_ANDX_Request(self, data):
        """
        parse TREE_CONNECT request message to extract the Request_Path
        """
        try:
            wct, andxcmd, rsrv1, andxoffset, flags, passwordlength, bytecount = struct.unpack(
                '<BBBHHHH', data[:11])
            if bool(passwordlength % 2):
                pwpadlen = 0
            else:
                pwpadlen = 1
            rp_offset = 11 + passwordlength + pwpadlen
            rplen = data[rp_offset:].find('\x00\x00') + 1
            request_path = data[rp_offset:rp_offset + rplen]
            return request_path
        except:
            return ''


class NTLMSSP_AUTH_RECORD():

    """
    self.messagetype
    self.lanman_response 	#
    self.ntlm_response 	#
    self.domain_name 	# Domain the client is attempting to autheticate too
    self.user_name 		# Username of the account your attempting to authenticate too
    self.host_name 		# Hostname of the machine your attempting to connect too
    self.sessionkey 	# Will be 0x0000000000 by default for the client
    self.nativeos 		# String representation of the client's Native Operating System (unicode)
    self.nativelanman 	# String representation of the client's LAN manager type (unicode)
    self.primary_domain 	# representation of the client's DOMAIN (int)
    self.valid		# Is it a valid NTLMSSP_AUTH request
    """

    def __init__(self, secblob):
        self.valid = False
        try:

            # Message Type
            self.messagetype = struct.unpack('<I', secblob[8:12])[0]

            # parse Lan Manager Response
            lanmanlen, lanmanmaxlen, lanmanoffset = struct.unpack(
                '<HHI', secblob[12:20])
            if lanmanlen == 0:
                self.lanman_response = 'emtpy'
            else:
                self.lanman_response = secblob[
                    lanmanoffset:lanmanoffset + lanmanlen]

            # parse NTLM Response
            ntlmlen, ntlmmaxlen, ntlmoffset = struct.unpack(
                '<HHI', secblob[20:28])
            if ntlmlen == 0:
                self.ntlm_response = 'empty'
            else:
                self.ntlm_response = secblob[ntlmoffset:ntlmoffset + ntlmlen]

            # parse Domain Name
            domainnamelen, domainnamemaxlen, domainnameoffset = struct.unpack(
                '<HHI', secblob[28:36])
            self.domain_name = UTF16LEtoUTF8(
                secblob[domainnameoffset:domainnameoffset + domainnamelen])

            # parse User Name
            usernamelen, usernamemaxlen, usernameoffset = struct.unpack(
                '<HHI', secblob[36:44])
            self.user_name = UTF16LEtoUTF8(
                secblob[usernameoffset:usernameoffset + usernamelen])

            # parse Host Name
            hostnamelen, hostnamemaxlen, hostnameoffset = struct.unpack(
                '<HHI', secblob[44:52])
            self.host_name = UTF16LEtoUTF8(
                secblob[hostnameoffset:hostnameoffset + hostnamelen])

            # parse Session Key
            sessionkeylen, sessionkeymaxlen, sessionkeyoffset = struct.unpack(
                '<HHI', secblob[52:60])
            self.sessionkey = secblob[
                sessionkeyoffset:sessionkeyoffset + sessionkeylen]

            # parse NTLMSSP Flags
            self.flags = struct.unpack('<I', secblob[60:64])[0]
            self.valid = True

        except:
            pass


class NTLMSSP_CHALLENGE_RECORD():

    """
    self.target_name      # Domain name of server
    self.server_challenge # NTLM Server Challenge, a 64-bit nonce.
    ...
    Other values not implemented yet
    ...
    self.valid		        # Is it a valid NTLMSSP_CHALLENGE request
    """

    def __init__(self, secblob):
        self.valid = False
        try:

            # Message Type
            self.messagetype = struct.unpack('<I', secblob[8:12])[0]

            # parse Lan Manager Response
            targetlen, targetmaxlen, targetoffset = struct.unpack(
                '<HHI', secblob[12:20])
            if targetlen == 0:
                self.target_name = 'emtpy'
            else:
                self.target_name = UTF16LEtoUTF8(
                    secblob[targetoffset:targetoffset + targetlen])

            # server challenge
            self.server_challenge = secblob[24:32]

            # Set valid flag
            self.valid = True

        except:
            pass


def UTF16LEtoUTF8(inbytes):
    try:
        return unicode(inbytes, 'utf-16-le').encode('utf-8')
    except:
        return inbytes


class displaystub(dshell.Decoder):

    def __init__(self):
        dshell.Decoder.__init__(self,
                                name='smbdecoder',
                                description='Intermediate class to support SMB based decoders.',
                                longdescription="See source code or pydoc for details on use."
                               )

if __name__ == '__main__':
    dObj = displaystub()
    print dObj
else:
    dObj = displaystub()
