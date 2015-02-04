#!/usr/bin/env python

import dshell
import output
import util


class DshellDecoder(dshell.TCPDecoder):

    '''generic session-level decoder template'''

    def __init__(self, **kwargs):
        '''decoder-specific config'''

        '''pairs of 'option':{option-config}'''
        self.optiondict = {}

        '''bpf filter, for ipV4'''
        self.filter = ''
        '''filter function'''
        # self.filterfn=

        '''init superclasses'''
        self.__super__().__init__(**kwargs)

    def packetHandler(self, udp, data):
        '''handle UDP as Packet(),payload data
                remove this if you want to make UDP into pseudo-sessions'''
        pass

    def connectionInitHandler(self, conn):
        '''called when connection starts, before any data'''
        pass

    def blobHandler(self, conn, blob):
        '''handle session data as soon as reassembly is possible'''
        pass

    def connectionHandler(self, conn):
        '''handle session once all data is reassembled'''
        pass

    def connectionCloseHandler(self, conn):
        '''called when connection ends, after data is handled'''

# create an instance at load-time
dObj = DshellDecoder()
