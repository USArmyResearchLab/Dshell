import dshell
import util
import colorout
#from impacket.ImpactDecoder import EthDecoder
import datetime
import sys
import traceback
import logging

# import any other modules here
import cgi


class DshellDecoder(dshell.TCPDecoder):

    def __init__(self):
        dshell.TCPDecoder.__init__(self,
                                   name='connectionssummary',
                                   description='Generates a summary of the connections',
                                   longdescription="""
Generates a summary of the connections within the pcap

Example:
  
  decode -d connectionssummary --ebpf 'port 80' mypcap.pcap
  decode -d connectionssummary --ebpf 'port 80' mypcap.pcap -o file.html 

""",
                                   filter="tcp",
                                   author='bms'
                                   #TO BE CHANGED
                                   #optiondict={
                                   #    'hex': {'action': 'store_true', 'help': 'two-column hex/ascii output'},
                                   #    'time': {'action': 'store_true', 'help': 'include timestamp for each blob'},
                                   #    'encoding': {'type': 'string', 'help': 'attempt to interpret text as encoded with specified schema'},
                                   #}
                                   )
        self.out = colorout.ColorOutput()

    def __errorHandler(self, blob, expected, offset, caller):
        # Custom error handler that is called when data in a blob is missing or
        # overlapping
        if offset > expected:  # data is missing
            self.data_missing_message += "[%d missing bytes]" % (
                offset - expected)
        elif offset < expected:  # data is overlapping
            self.data_missing_message += "[%d overlapping bytes]" % (
                offset - expected)
        return True

    def preModule(self):
        self.connectionCount = 0
        # Reset the color mode, in case a file is specified
        self.out.setColorMode()
        # Used to indicate when data is missing or overlapping
        self.data_missing_message = ''
        # overwrite the output module's default error handler
        self.out.errorH = self.__errorHandler
        # variables to store connection details until after pcap is decoded
        self.connectionNumber = []
        self.connectionStart = []
        self.connectionClientBytes = []
        self.connectionServerBytes = []
        self.connectionPackets = []

    def connectionHandler(self, connection):

        try:

            # Skip Connections with no data transferred
            if connection.clientbytes + connection.serverbytes < 1:
                return

            # Update Connection Counter
            self.connectionCount += 1

            # Connection Header Information Store For PostModule()
            # FIX LINE LENGTH
            self.connectionNumber.append("Connection %d (%s)\n" % (self.connectionCount, str(connection.proto)))
            self.connectionStart.append("Start: %s UTC\n  End: %s UTC\n" % (datetime.datetime.utcfromtimestamp(connection.starttime), datetime.datetime.utcfromtimestamp(connection.endtime)))
            self.connectionClientBytes.append("%s:%s -> %s:%s (%d bytes) (%d packets)\n" % (connection.clientip, connection.clientport,connection.serverip, connection.serverport, connection.clientbytes, connection.clientpackets))
            self.connectionServerBytes.append("%s:%s -> %s:%s (%d bytes) (%d packets)\n" % (connection.serverip, connection.serverport,connection.clientip, connection.clientport, connection.serverbytes, connection.serverpackets))

        except KeyboardInterrupt:
            raise
        except:
            print 'Error in connectionHandler: ', sys.exc_info()[1]
            traceback.print_exc(file=sys.stdout)
    
    def postModule(self):
        try:
            self.out.write("%s\n" % "Connections Summary",formatTag="H2", direction="cs")
            self.out.write("%d %s\n" % (self.connectionCount,"Connections"),formatTag="H2", direction="cs")
            self.out.write("\n")
            for number, start, client, server in zip(self.connectionNumber, self.connectionStart, self.connectionClientBytes, self.connectionServerBytes):
                self.out.write(number)
                self.out.write(start)
                self.out.write(client)
                self.out.write(server)
                self.out.write("\n")
        except:
            print 'Error in postModule: ', sys.exc_info()[1]
            traceback.print_exc(file=sys.stdout)


if __name__ == '__main__':
    dObj = DshellDecoder()
    print dObj
else:
    dObj = DshellDecoder()
