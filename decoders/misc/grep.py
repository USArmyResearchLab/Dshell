import dshell
import datetime
import sys

# import any other modules here
import re


class grepDecoder(dshell.TCPDecoder):

    def __init__(self):
        dshell.TCPDecoder.__init__(self,
                                   name='grep',
                                   description='Search for patterns in streams.',
                                   longdescription="""
Grep is a utility decoder, useful on it's own or in combination with
downstream (chained) decoders.  Your search expression is specified with the 
--grep_expression option, and the default behavior is that the entire "line"
of text surround each match will be printed, along with the standard
connection information.  However, granular match information is passed to the
output decoder giving the user more control about the type of output they
would like to see.  Following is the named-variable convention passed to
output:

   match:  Full expression match
   m1:     First sub-match
   m2:     Second sub-match
   ..
   mn:     N'th sub-match

Examples:

  Snag User-Agent, display as CSV:

     decode -d grep --grep_ignorecase --grep_expression 'User-Agent: (.*?)$' --output csvout,m1

        The text following User-Agent will be the first sub-match and then
        printed as a named field in CSV output.

  Better yet:

     decode -d grep --grep_ignorecase --grep_expression 'User-Agent: (.*?)$' --oformat "%(m1)s"
 
        This uses the same expression but instead of the default output,
        specifies "m1" in a format string which makes it the ONLY value 
        displayed.  This is nice for piping into sort/uniq or other 
        command-line filters.

Iterative matching

Rather than alerting on an entire line or just the first hit within that line,
Python's regular expression module offers a function called "finditer" which
scans across input text and provides an iterable object of ALL the matches. 
So with "--grep_iterate" we can use that.

Examples:

  Simplistically grab all hyperlinks and dump to stdout:

     decode -d grep --grep_expression '<a .*?href=\"(.*?)\".*?\/?>' --grep_iterate --grep_ignorecase --oformat "%(m1)s"

Chainable

Grep is chainable.  What does this mean?  If data within a connection
matches a grep expression, the entire connection is considered a "hit" and is
then allowed to be processed by subDecoders.  Non-hits are dropped.

So this means you can search for an expression and view all matching
connections in followstream, or process all as web traffic, etc.

Examples:

  View all web traffic that originated from Windows 7 machines:

     decode -d grep+web --grep_ignorecase --grep_expression 'User-Agent: [^\\r\\n]*Windows 6.1'
""",
                                   author='amm',
                                   filter='tcp',
                                   optiondict={
                                       'expression': {'type': 'string', 'help': 'Search expression'},
                                       'ignorecase': {'action': 'store_true', 'help': 'Case insensitive search.'},
                                       'singleline': {'action': 'store_true', 'help': 'Treat entire connection as single line of text.'},
                                       'iterate': {'action': 'store_true', 'help': 'Iterate hits on match string.'},
                                       'invert': {'action': 'store_true', 'help': 'For chained only: Invert hit results.'}
                                   }
                                   )
        self.chainable = True

    def preModule(self):

        #
        # Does subdecoder have a blobHandler
        #
        if self.subDecoder and 'blobHandler' in dir(self.subDecoder):
            self.debug("subDecoder has blobHandler")
            self.subblobHandler = True
            # Indexed by connection, storage for all blobs being deferred
            self.deferredBlobs = {}
        else:
            self.subblobHandler = False

        # Pass/Drop dictionary of connections to use in chain mode
        self.connstate = {}

        # Must use singleLine mode when subDecoder is present
        if self.subDecoder:
            self.singleline = True

        # Re parameters
        self.reFlags = 0
        if self.ignorecase:
            self.reFlags = self.reFlags | re.IGNORECASE
        if self.singleline or self.iterate:
            self.reFlags = self.reFlags | re.S

        # Re Expression -> Object
        if self.expression == None or not len(self.expression):
            self.error(
                "Must specify expression using --%s_expression" % self.name)
            sys.exit(1)
        else:
            sys.stderr.write("Using expression: '%s'\n" % self.expression)
            self.reObj = re.compile(self.expression, self.reFlags)

        dshell.TCPDecoder.preModule(self)

    def errorH(self, **x):
        # custom errorHandler here
        pass

    def blobHandler(self, connection, blob):
        # Defer all Blob processing until the connection is handled, so we can
        # grep the entire connection stream
        if self.subblobHandler:
            if connection not in self.deferredBlobs:
                self.deferredBlobs[connection] = []
            self.deferredBlobs[connection].append(blob)

    def connectionHandler(self, connection):

        # Normal processing, no subDecoder
        if not self.subDecoder:
            self.__searchStream(connection.data(direction='cs', errorHandler=self.errorH) +
                                "\n" + connection.data(direction='sc', errorHandler=self.errorH), connection)
            return

        # Call sub blobHandler for all blobs
        if self.subblobHandler and self.__connectionTest(connection):
            self.debug("Preparing to process %d blobs in subdecoder" %
                       len(self.deferredBlobs))
            for b in self.deferredBlobs[connection]:
                self.subDecoder.blobHandler(connection, b)
            self.deferredBlobs[connection] = None

        # Call sub connectionHandler if necessary
        if 'connectionHandler' in dir(self.subDecoder) and self.__connectionTest(connection):
            self.subDecoder.connectionHandler(connection)

    def __alert(self, conn, hitstring, matchObj):
        kwargs = {'match': matchObj.group(0)}
        matchNumber = 0
        for mgroup in matchObj.groups():
            matchNumber += 1
            kwargs['m' + str(matchNumber)] = mgroup
        self.alert(hitstring, kwargs, **conn.info())

    def __connectionTest(self, connection):
        if connection not in self.connstate:
            if self.reObj.search(connection.data(direction='cs', errorHandler=self.errorH) + "\n" + connection.data(direction='sc', errorHandler=self.errorH)):
                self.connstate[connection] = True
            else:
                self.connstate[connection] = False
            if self.invert:
                self.connstate[connection] = not self.connstate[connection]
        if self.connstate[connection]:
            return True
        else:
            return False

    def __searchStream(self, d, conn):

        if self.singleline or self.iterate:
            self.__runSearch(d, conn)
        else:
            lines = d.split('\n')
            for l in lines:
                l = l.rstrip()
                self.__runSearch(l, conn)

    def __runSearch(self, d, conn):
        if self.iterate:
            for m in self.reObj.finditer(d):
                self.__alert(conn, m.group(0), m)
        else:
            m = self.reObj.search(d)
            if m:
                self.__alert(conn, d, m)


# always instantiate an dObj of the class
if __name__ == '__main__':
    dObj = grepDecoder()
    print dObj
else:
    dObj = grepDecoder()
