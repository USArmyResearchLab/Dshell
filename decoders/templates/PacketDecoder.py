#!/usr/bin/env python

import dshell
import output
import util


class DshellDecoder(dshell.IPDecoder):

    '''generic packet-level decoder template'''

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

    def packetHandler(self, ip):
        '''handle as Packet() ojects'''
        pass

# create an instance at load-time
dObj = DshellDecoder()
