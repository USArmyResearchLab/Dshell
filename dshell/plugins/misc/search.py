import dshell.core
from dshell.util import printable_text
from dshell.output.alertout import AlertOutput

import re
import sys

class DshellPlugin(dshell.core.ConnectionPlugin):

    def __init__(self):
        super().__init__(
            name="search",
            author="dev195",
            bpf="tcp or udp",
            description="Search for patterns in connections",
            longdescription="""
Reconstructs streams and searches the content for a user-provided regular
expression. Requires definition of the --search_expression argument. Additional
options can be provided to alter behavior.
            """,
            output=AlertOutput(label=__name__),
            optiondict={
                "expression": {
                    "help": "Search expression",
                    "type": str,
                    "metavar": "REGEX"},
                "ignorecase": {
                    "help": "Ignore case when searching",
                    "action": "store_true"},
                "invert": {
                    "help": "Return connections that DO NOT match expression",
                    "action": "store_true"},
                "quiet": {
                    "help": "Do not display matches from this plugin. Useful when chaining plugins.",
                    "action": "store_true"}
            })



    def premodule(self):
        # make sure the user actually provided an expression to search for
        if not self.expression:
            self.error("Must define an expression to search for using --search_expression")
            sys.exit(1)

        # define the regex flags, based on arguments
        re_flags = 0
        if self.ignorecase:
            re_flags = re_flags | re.IGNORECASE

        # Create the regular expression
        try:
            # convert expression to bytes so it can accurately compare to
            # the connection data (which is also of type bytes)
            byte_expression = bytes(self.expression, 'utf-8')
            self.regex = re.compile(byte_expression, re_flags)
        except Exception as e:
            self.error("Could not compile regex ({0})".format(e))
            sys.exit(1)



    def connection_handler(self, conn):
        """
        Go through the data of each connection.
        If anything is a hit, return the entire connection.
        """

        match_found = False
        for blob in conn.blobs:
            for line in blob.data.splitlines():
                match = self.regex.search(line)
                if match and self.invert:
                    return None
                elif match and not self.invert:
                    match_found = True
                    if not self.quiet:
                        if blob.sip == conn.sip:
                            self.write(printable_text(line, False), **conn.info(), dir_arrow="->")
                        else:
                            self.write(printable_text(line, False), **conn.info(), dir_arrow="<-")
                elif self.invert and not match:
                    if not self.quiet:
                        self.write(**conn.info())
                    return conn
        if match_found:
            return conn



if __name__ == "__main__":
    print(DshellPlugin())
