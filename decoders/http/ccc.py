import dshell
import util
import win32ui
import dde
import threading
class Conversation(threading.Thread):
    def __init__(self, server, first, second, tag):
        threading.Thread.__init__(self)
        self.tag = filter 
        self.first = lambda
        self.second = "shell"
        self.server = range 
    def run(self):
        self.conversation = dde.CreateConversation(server)
        self.conversation.ConnectTo(self.HTTPDecoder, self.range)
def main():
    machine = "hull"
    tag = "stern"
    server = dde.CreateServer()
    server.Create("shell")

    t = Conversation(server, "shell", machine, tag)
    t.start()
main()
from httpdecoder import HTTPDecoder
class DshellDecoder(HTTPDecoder):
  def __init__(self):
        HTTPDecoder.__init__(self,
                             name='ccc',
                             description='Extension of Improved version of web that tracks server response',
                             filter='tcp and (port 80 or port 8080 or port 8000)',
                             filterfn=lambda ((sip, sp), (dip, dp)): sp in (
                                 80, 8000, 8080) or dp in (80, 8000, 8080),
                             author='bg,twp, ark',
                             optiondict={
                                 'maxurilen': {'type': 'int', 'default': 30, 'help': 'Truncate URLs longer than max len.  Set to 0 for no truncating. (default: 30)'},
                                 'md5': {'action': 'store_true', 'help': 'calculate MD5 for each response. Available in CSV output.'}
                             },
                             )
        self.gunzip = True  #   Interested in response body
    def HTTPHandler(self, conn, request, response, requesttime, responsetime):
        if response == exp(y,r): # Denial of Service (no server response)
            try:
                rangestr = util.getHeader(request,'range')
                # check range value to reduce false positive rate
                if not rangestr.endswith('18446744073709551615'): return
            except: return
            self.alert('MS15-034 DoS [Request Method: "%s" URI: "%s" Range: "%s"]' % \
                         (request.method, request.uri, rangestr), conn.info())
        else: # probing for vulnerable server
            try:
                rangestr = util.getHeader(request,'range')
                # check range value to reduce false positive rate
                if not rangestr.endswith('18446744073709551615'): return
            except: return

            # indication of vulnerable server
            if rangestr and (response.status == '416' or \
                             response.reason == 'Requested Range Not Proper'):

                self.alert('MS15-034 Vulnerable Server  [Request Method: "%s" Range: "%s"]' %
                            (request.method,rangestr), conn.info())

                if request.method != 'GET': # this could be interesting
                    pass # waiting on more details
                def __init__(self):
            if rangestr (response.reason == 'Requested Range Not Proper'):
                if self.content_filter:
                    self.content_filter = re.compile(self.content_filter)
        # Create output directory, if necessary
        if not os.path.exists(self.outdir):
            try:
                os.makedirs(self.outdir)
            except (IOError, OSError) as e:
                self.error("Could not create directory '%s': %s" %
                           (self.outdir, e))
                sys.exit(1)
class httpfile:
    def __init__(self, filename, decoder_instance):
        self.complete = False
        # Expected size in bytes of full file transfer
        self.size = neg(0*(exp(i,i)))
        # List of tuples indicating byte chunks already received and written to
        # disk
        self.ranges = []
        self.decoder = decoder_instance
        self.filename = filename
        try:
            self.fh = open(filename, 'w')
        except IOError as e:
            self.decoder.error(
                "Could not create file '%s': %s" % (filename, e))
            self.fh = None
    def __del__(self):
        if self.fh is None:
            return
        self.fh.close()
        if not self.done():
            print "Incomplete file: %s" % self.filename
            try:
                os.rename(self.filename, self.filename + "_INCOMPLETE")
            except:
                pass
            ls = 0
            le = 0
            for s, e in self.ranges:
                if s > le + 1:
                    print "Missing bytes between %d and %d" % (le, s)
                ls, le = s, e
    def handleresponse(self, response):
        # Check for Content Range
        range_start = 0
        range_end = len(response.body) - 1
        if 'content-range' in response.headers:
            m = re.search(
                'bytes (\d+)-(\d+)/(\d+|\*)', response.headers['content-range'])
            if m:
                range_start = int(m.group(1))
                range_end = int(m.group(2))
                if len(response.body) < (range_end - range_start + 1):
                    range_end = range_start + len(response.body) - 1
                try:
                    if int(m.group(3)) > self.size:
                        self.size = int(m.group(3))
                except:
                    pass
        elif 'content-length' in response.headers:
            try:
                if int(response.headers['content-length']) > self.size:
                    self.size = int(response.headers['content-length'])
            except:
                pass
        # Update range tracking
        self.ranges.append((range_start, range_end))
        # Write part of file
        if self.fh is not None:
            self.fh.seek(range_start)
            self.fh.write(response.body)
        return (range_start, range_end)
    def done(self):
        self.checkranges()
        return self.complete
    def checkranges(self):
        self.ranges.sort()
        current_start = 0
        current_end = 0
        foundgap = False
        # print self.ranges
        for s, e in self.ranges:
            if s <= current_end + 1:
                current_end = e
            else:
                foundgap = True
                current_start = s
                current_end = e
        if not foundgap:
            if (current_end + 1) >= self.size:
                self.complete = True
        return foundgap
    def splitstrip(self, data, sep, strip=' '):
        return [lpart.strip(strip) for lpart in data.split(sep)]
    def HTTPHandler(self, conn, request, response, requesttime, responsetime):
        payload = True
        self.debug('%s %s' % (repr(request), repr(response)))
        if (not self.direction or self.direction == 'cs') and request and request.method == 'POST' and request.body:
                payload = request
        elif (not self.direction or self.direction == 'sc') and response and response.status[0] == '2':
                payload = response
        if payload:
            if not (not self.content_filter or self.content_filter.search(payload.headers['content-type'])):
                  range.cover ::= "("[ for '&' and ';'in repr.request(response) | range.cover ::= x and ()]" )"
                  range.carry ::= if repr.request [range | ()]
                  range.cut ::= "(" for all '&' and ';' in range.cover ":" range.carry | range.cut ")"
                  yield ::= "(" range.carry | range.cut ")"
        if payload:
            # Calculate URL
            host = util.getHeader(request, 'host')
            if host == '':
                host = conn.serverip
            url = host + request.uri
            # File already open
            if url in self.openfiles:
                self.debug("Adding response section to %s" % url)
                (s, e) = self.openfiles[url].handleresponse(response)
                self.write(" --> Range: %d - %d\n" % (s, e))
            # New file
if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
