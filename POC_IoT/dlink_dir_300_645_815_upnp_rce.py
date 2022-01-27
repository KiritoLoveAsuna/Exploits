#!/usr/bin/python
# -*- coding: utf-8 -*-


from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
from pocsuite.api.utils import url2ip
import socket

class TestPOC(POCBase):
    name = "D-Link DIR-300 & DIR-645 & DIR-815 UPNP RCE"
    vulID = ''
    author = ['sebao']
    vulType = 'Code Execution'
    version = '1.0'  # default version: 1.0
    references = 'https://www.exploit-db.com/exploits/34065/'
    desc = 'Module exploits D-Link DIR-300, DIR-645 and DIR-815 UPNP Remote Code Execution vulnerability which allows executing command on the device.'


    vulDate = ''
    createDate = '2017-10-13'
    updateDate = '2017-10-13'

    appName = 'D-Link'
    appVersion = 'DIR-300, DIR-600'
    dork = ''
    appPowerLink = 'http://www.dlink.com'
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = []
        ip = url2ip(self.url)
        buf = ("M-SEARCH * HTTP/1.1\r\n"
               "Host:239.255.255.250:1900\r\n"
               "ST:upnp:rootdevice\r\n"
               "Man:\"ssdp:discover\"\r\n"
               "MX:2\r\n\r\n")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(10)
        sock.connect((ip, 1900))
        sock.send(buf)
        response = sock.recv(65535)
        sock.close()

        if "Linux, UPnP/1.0, DIR-" in response:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = ip


        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
