import util
import hashlib
import os
from httpdecoder import HTTPDecoder


class DshellDecoder(HTTPDecoder):

    # Constant for dump directory
    __OUTDIR = 'flashout'

    # Constants for MD5sum option
    NOMD5 = 0
    MD5 = 1
    MD5_EXPLICIT_FILENAME = 2

    def __init__(self):
        HTTPDecoder.__init__(self,
                             name='flash-detect',
                             description='Detects successful Flash file download.',
                             filter='tcp and (port 80 or port 8080 or port 8000)',
                             filterfn=lambda ((sip, sp), (dip, dp)): sp in (
                                 80, 8000, 8080) or dp in (80, 8000, 8080),
                             optiondict={
                                 'dump': {'action': 'store_true', 'help': '''\
Dump the flash file to a file based off its name, md5sum (if specified), or
its URI. The file is dumped to the local directory "flashout". The file
extension is ".flash" to prevent accidental execution.'''
                                          },
                                 'md5sum': {'type': 'int', 'default': 0, 'help': '''\
Calculate and print the md5sum of the file. There are three options:
  0: (default) No md5sum calculations or labeling

  1: Calculate md5sum; Print out md5sum in alert; Name all dumped files by
their md5sum (must be used with 'dump' option)

  2: Calculate md5sum; Print out md5sum in alert; If found, a file's explicitly
listed save name (found in 'content-disposition' HTTP header) will be used
for file dump name instead of md5sum.

Any other numbers will be ignored and the default action will be used.'''
                                            }
                             },
                             longdescription='''\
flash-detect identifies HTTP requests where the server response contains a Flash
file.  Many exploit kits utilize Flash to deliver exploits to potentially vulnerable
browsers.  If a flash file is successfully downloaded, an alert will occur stating
the full URL of the downloaded file, its content-type, and (optionally) its md5sum.

Usage Examples:
===============
  Search all pcap files for Flash file downloads, and upon detection, calculate
  and print alerts containing the md5sum to screen:

    decode -d flash-detect --flash-detect_md5sum=1 *.pcap

  If you wanted to save every detected Flash file to a local directory
  "./flashout/" with its md5sum as the file name:

    decode -d flash-detect --flash-detect_md5sum=1 --flash-detect_dump *.pcap
  The output directory can be changed by modifying the `__OUTDIR` variable.

  An example of a real pcap file, taken from
  http://malware-traffic-analysis.net/2014/12/12/index.html:
    decode -d flash-detect --flash-detect_md5sum=1 2014-12-12-Nuclear-EK-traffic.pcap

        The following text should be displayed in the output, and the md5sum
        can be checked on a site like virustotal:
** yquesrerman.ga/AwoVG1ADAw4OUhlVDlRTBQoHRUJTXVYOUVYaAwtGXFRVVFxXVwBOVRtA (application/octet-stream) md5sum: 9b3ad66a2a61e8760602d98b537b7734 **

Implementation Logic
====================

1.  Check if the HTTP response status is 200 OK

2.  Test the content-type of the HTTP response for the follwing strings:
          'application/x-shockwave-flash'
          'application/octet-stream'
          'application/vnd.adobe.flash-movie'

3.  Test filedownload following known Flash magic byte substrings:
         'CWS'
         'ZWS'
         'FWS'

Note: Encoded or obfuscated flash files will *not* be detected.

Chainable

flash-detect is chainable. If a connection contains an HTTP response with a
successful Flash file download, then the entire connection (in the case of a
connectionHandler), and the request, response, requesttime, and responsetime
(in the case of an HTTPHandler) is/are passed to the subDecoders for additional
processing. Undetected or non-Flash files are dropped.
''',
                             author='ekilmer',
                             )
        self.chainable = True

    def preModule(self):
        # Attempt to create output directory
        if self.dump:
            self.__OUTDIR = self.__mkoutdir(self.__OUTDIR)
            self.log("Using output directory: {0}".format(self.__OUTDIR))

    def HTTPHandler(self, conn, request, response, requesttime, responsetime):
        if response and response.status != '200':
            return

        content_type = util.getHeader(response, 'content-type')
        if content_type not in ('application/x-shockwave-flash',
                                'application/octet-stream',
                                'application/vnd.adobe.flash-movie'):
            return

        # Check for known flash file header characters
        if not response.body.startswith(('CWS', 'ZWS', 'FWS')):
            return

        host = util.getHeader(request, 'host')
        # Grab file info as dict with keys: 'file_name', 'md5sum', 'uri'
        file_info = self.get_file_info(request, response)
        if self.md5sum == self.MD5 or self.md5sum == self.MD5_EXPLICIT_FILENAME:
            # Print MD5 sum in the alert
            self.alert('{0}{1} ({2})  md5sum: {3}'.format(host, request.uri, content_type,
                                                          file_info['md5sum']), **conn.info())
        else:
            self.alert('{0}{1} ({2})'.format(host, request.uri, content_type), **conn.info())

        # Dump the file if chosen
        if self.dump:
            # Name output files based on options
            if self.md5sum == self.MD5:
                origname = file_info['md5sum']
            # Check for explicitly listed filename
            elif file_info['file_name']:
                origname = file_info['file_name']
            # If explicit name not found, but still want MD5, give it MD5
            elif self.md5sum == self.MD5_EXPLICIT_FILENAME:
                origname = file_info['md5sum']
            # Else name the file by its URI (which can be long)
            else:
                origname = file_info['uri']
            outname = self.__localfilename(self.__OUTDIR, origname)
            with open('{0}.flash'.format(outname), 'wb') as outfile:
                outfile.write(response.body)

        # Pass to subdecoder if necessary
        if 'HTTPHandler' in dir(self.subDecoder):
            self.subDecoder.HTTPHandler(conn, request, response, requesttime, responsetime)
        elif 'connectionHandler' in dir(self.subDecoder):
            self.subDecoder.connectionHandler(conn)

    def get_file_info(self, request, response):
        """Checks for an explicitly listed file name. Returns a dictionary containing the
        explicitly listed filename (if present), the URI, and an md5sum (if requested)
        """
        file_info = {'file_name': '', 'uri': '', 'md5sum': ''}

        content = util.getHeader(response, 'content-disposition')
        if content and 'filename' in content:
            # RFC 1806: content contains a string with parameters separated by semi-colons
            text = content.split(';')
            for parm in text:
                if parm.strip().startswith('filename='):
                    file_info['file_name'] = parm.split('filename=', 1)[1]

        # CAVEAT: When the URI is very long and it is used as a filename in a dump,
        # then the file name may become unwieldy
        file_info['uri'] = request.uri

        if self.md5sum == self.MD5 or self.md5sum == self.MD5_EXPLICIT_FILENAME:
            file_info['md5sum'] = self.__body_md5(response)

        return file_info

    def __body_md5(self, response):
        """Calculate the MD5sum(hex) of the body portion of the response."""
        if len(response.body) > 0:
            return hashlib.md5(response.body.rstrip('\0')).hexdigest()
        else:
            self.warn("Nothing to hash")
            return ''

    def __mkoutdir(self, outdir):
        """Creates output directory.  Returns full path to output directory."""
        path = os.path.realpath(outdir)
        if os.path.exists(path):
            return path
        try:
            os.mkdir(path)
            return path
        except OSError:
            # most likely a permission denied issue, continue and try system temp directory
            pass
        except:
            self.warn('Unable to create a directory for file dump')
            # other errors, abort
            raise

        # Trying temp directory
        if os.path.exists('/tmp'):
            path = os.path.realpath(os.path.join('/tmp', outdir))
        if os.path.exists(path):
            return path
        try:
            os.mkdir(path)
            return path
        except:
            self.warn('Unable to create a directory for file dump')
            raise

    def __localfilename(self, path, origname):
        """Generate a local (extracted) filename based on the original"""
        tmp = origname.replace('\\', '_')
        tmp = tmp.replace('/', '_')
        tmp = tmp.replace(':', '_')
        localname = ''
        for c in tmp:
            if ord(c) > 32 and ord(c) < 127:
                localname += c
            else:
                localname += '%{0:02X}'.format(ord(c))
        localname = '{0}/{1}'.format(path, localname)
        postfix = ''
        i = 0
        while os.path.exists(localname+postfix):
            i += 1
            postfix = '_{0:02d}'.format(i)
        return localname+postfix

if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
